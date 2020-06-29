// +build !js

package webrtc

import (
	"math/big"
	"math/rand"
	"testing"

	"crypto/rsa"
	"crypto/x509"

	"github.com/pion/sdp/v2"
	"github.com/stretchr/testify/assert"
)

func TestExtractFingerprint(t *testing.T) {
	t.Run("Good Session Fingerprint", func(t *testing.T) {
		s := &sdp.SessionDescription{
			Attributes: []sdp.Attribute{{Key: "fingerprint", Value: "foo bar"}},
		}

		fingerprint, hash, err := extractFingerprint(s)
		assert.NoError(t, err)
		assert.Equal(t, fingerprint, "bar")
		assert.Equal(t, hash, "foo")
	})

	t.Run("Good Media Fingerprint", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{Attributes: []sdp.Attribute{{Key: "fingerprint", Value: "foo bar"}}},
			},
		}

		fingerprint, hash, err := extractFingerprint(s)
		assert.NoError(t, err)
		assert.Equal(t, fingerprint, "bar")
		assert.Equal(t, hash, "foo")
	})

	t.Run("No Fingerprint", func(t *testing.T) {
		s := &sdp.SessionDescription{}

		_, _, err := extractFingerprint(s)
		assert.Equal(t, ErrSessionDescriptionNoFingerprint, err)
	})

	t.Run("Invalid Fingerprint", func(t *testing.T) {
		s := &sdp.SessionDescription{
			Attributes: []sdp.Attribute{{Key: "fingerprint", Value: "foo"}},
		}

		_, _, err := extractFingerprint(s)
		assert.Equal(t, ErrSessionDescriptionInvalidFingerprint, err)
	})

	t.Run("Conflicting Fingerprint", func(t *testing.T) {
		s := &sdp.SessionDescription{
			Attributes: []sdp.Attribute{{Key: "fingerprint", Value: "foo"}},
			MediaDescriptions: []*sdp.MediaDescription{
				{Attributes: []sdp.Attribute{{Key: "fingerprint", Value: "foo blah"}}},
			},
		}

		_, _, err := extractFingerprint(s)
		assert.Equal(t, ErrSessionDescriptionConflictingFingerprints, err)
	})
}

func TestExtractICEDetails(t *testing.T) {
	const defaultUfrag = "defaultPwd"
	const defaultPwd = "defaultUfrag"

	t.Run("Missing ice-pwd", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{Attributes: []sdp.Attribute{{Key: "ice-ufrag", Value: defaultUfrag}}},
			},
		}

		_, _, _, err := extractICEDetails(s)
		assert.Equal(t, err, ErrSessionDescriptionMissingIcePwd)
	})

	t.Run("Missing ice-ufrag", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{Attributes: []sdp.Attribute{{Key: "ice-pwd", Value: defaultPwd}}},
			},
		}

		_, _, _, err := extractICEDetails(s)
		assert.Equal(t, err, ErrSessionDescriptionMissingIceUfrag)
	})

	t.Run("ice details at session level", func(t *testing.T) {
		s := &sdp.SessionDescription{
			Attributes: []sdp.Attribute{
				{Key: "ice-ufrag", Value: defaultUfrag},
				{Key: "ice-pwd", Value: defaultPwd},
			},
			MediaDescriptions: []*sdp.MediaDescription{},
		}

		ufrag, pwd, _, err := extractICEDetails(s)
		assert.Equal(t, ufrag, defaultUfrag)
		assert.Equal(t, pwd, defaultPwd)
		assert.NoError(t, err)
	})

	t.Run("ice details at media level", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{
					Attributes: []sdp.Attribute{
						{Key: "ice-ufrag", Value: defaultUfrag},
						{Key: "ice-pwd", Value: defaultPwd},
					},
				},
			},
		}

		ufrag, pwd, _, err := extractICEDetails(s)
		assert.Equal(t, ufrag, defaultUfrag)
		assert.Equal(t, pwd, defaultPwd)
		assert.NoError(t, err)
	})

	t.Run("Conflict ufrag", func(t *testing.T) {
		s := &sdp.SessionDescription{
			Attributes: []sdp.Attribute{{Key: "ice-ufrag", Value: "invalidUfrag"}},
			MediaDescriptions: []*sdp.MediaDescription{
				{Attributes: []sdp.Attribute{{Key: "ice-ufrag", Value: defaultUfrag}, {Key: "ice-pwd", Value: defaultPwd}}},
			},
		}

		_, _, _, err := extractICEDetails(s)
		assert.Equal(t, err, ErrSessionDescriptionConflictingIceUfrag)
	})

	t.Run("Conflict pwd", func(t *testing.T) {
		s := &sdp.SessionDescription{
			Attributes: []sdp.Attribute{{Key: "ice-pwd", Value: "invalidPwd"}},
			MediaDescriptions: []*sdp.MediaDescription{
				{Attributes: []sdp.Attribute{{Key: "ice-ufrag", Value: defaultUfrag}, {Key: "ice-pwd", Value: defaultPwd}}},
			},
		}

		_, _, _, err := extractICEDetails(s)
		assert.Equal(t, err, ErrSessionDescriptionConflictingIcePwd)
	})
}

func TestTrackDetailsFromSDP(t *testing.T) {
	t.Run("Tracks unknown, audio and video with RTX", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{
					MediaName: sdp.MediaName{
						Media: "foobar",
					},
					Attributes: []sdp.Attribute{
						{Key: "mid", Value: "0"},
						{Key: "sendrecv"},
						{Key: "ssrc", Value: "1000 msid:unknown_trk_label unknown_trk_guid"},
					},
				},
				{
					MediaName: sdp.MediaName{
						Media: "audio",
					},
					Attributes: []sdp.Attribute{
						{Key: "mid", Value: "1"},
						{Key: "sendrecv"},
						{Key: "ssrc", Value: "2000 msid:audio_trk_label audio_trk_guid"},
					},
				},
				{
					MediaName: sdp.MediaName{
						Media: "video",
					},
					Attributes: []sdp.Attribute{
						{Key: "mid", Value: "2"},
						{Key: "sendrecv"},
						{Key: "ssrc-group", Value: "FID 3000 4000"},
						{Key: "ssrc", Value: "3000 msid:video_trk_label video_trk_guid"},
						{Key: "ssrc", Value: "4000 msid:rtx_trk_label rtx_trck_guid"},
					},
				},
				{
					MediaName: sdp.MediaName{
						Media: "video",
					},
					Attributes: []sdp.Attribute{
						{Key: "mid", Value: "3"},
						{Key: "sendonly"},
						{Key: "msid", Value: "video_stream_id video_trk_id"},
						{Key: "ssrc", Value: "5000"},
					},
				},
			},
		}

		tracks := trackDetailsFromSDP(nil, s)
		assert.Equal(t, 3, len(tracks))
		if _, ok := tracks[1000]; ok {
			assert.Fail(t, "got the unknown track ssrc:1000 which should have been skipped")
		}
		if track, ok := tracks[2000]; !ok {
			assert.Fail(t, "missing audio track with ssrc:2000")
		} else {
			assert.Equal(t, RTPCodecTypeAudio, track.kind)
			assert.Equal(t, uint32(2000), track.ssrc)
			assert.Equal(t, "audio_trk_label", track.label)
		}
		if track, ok := tracks[3000]; !ok {
			assert.Fail(t, "missing video track with ssrc:3000")
		} else {
			assert.Equal(t, RTPCodecTypeVideo, track.kind)
			assert.Equal(t, uint32(3000), track.ssrc)
			assert.Equal(t, "video_trk_label", track.label)
		}
		if _, ok := tracks[4000]; ok {
			assert.Fail(t, "got the rtx track ssrc:3000 which should have been skipped")
		}
		if track, ok := tracks[5000]; !ok {
			assert.Fail(t, "missing video track with ssrc:5000")
		} else {
			assert.Equal(t, RTPCodecTypeVideo, track.kind)
			assert.Equal(t, uint32(5000), track.ssrc)
			assert.Equal(t, "video_trk_id", track.id)
			assert.Equal(t, "video_stream_id", track.label)
		}
	})

	t.Run("inactive and recvonly tracks ignored", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{
					MediaName: sdp.MediaName{
						Media: "video",
					},
					Attributes: []sdp.Attribute{
						{Key: "inactive"},
						{Key: "ssrc", Value: "6000"},
					},
				},
				{
					MediaName: sdp.MediaName{
						Media: "video",
					},
					Attributes: []sdp.Attribute{
						{Key: "recvonly"},
						{Key: "ssrc", Value: "7000"},
					},
				},
			},
		}

		assert.Equal(t, 0, len(trackDetailsFromSDP(nil, s)))
	})
}

func TestHaveApplicationMediaSection(t *testing.T) {
	t.Run("Audio only", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{
					MediaName: sdp.MediaName{
						Media: "audio",
					},
					Attributes: []sdp.Attribute{
						{Key: "sendrecv"},
						{Key: "ssrc", Value: "2000"},
					},
				},
			},
		}

		assert.False(t, haveApplicationMediaSection(s))
	})

	t.Run("Application", func(t *testing.T) {
		s := &sdp.SessionDescription{
			MediaDescriptions: []*sdp.MediaDescription{
				{
					MediaName: sdp.MediaName{
						Media: mediaSectionApplication,
					},
				},
			},
		}

		assert.True(t, haveApplicationMediaSection(s))
	})
}

func TestMediaDescriptionFingerprints(t *testing.T) {

	engine := &MediaEngine{}
	engine.RegisterCodec(NewRTPH264Codec(DefaultPayloadTypeH264, 90000))
	engine.RegisterCodec(NewRTPOpusCodec(DefaultPayloadTypeOpus, 48000))

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: big.NewInt(0),
			E: 65537},
		D: big.NewInt(0),
		Primes: []*big.Int{
			big.NewInt(0),
			big.NewInt(0)}}

	priv.PublicKey.N.SetString("28797351613986386053553799925930523856556567114192281047262209832157609093808726167332754674311193610314657875506491138278042731907378585474871313858539972620506584990256230463055263267832879992278549860679656698948688583000439632452783407023880239480944921280007744201325920812272533869383647979379571567184966151661498617440635276895590409657305405652079399213839457000740924007510776041152563237619320062950310310438147558795039302932064921857560398083339872243152893560088753009260598409134324107854684242358180483795713733484804681247651783660486476023730134351951739801106571526219927868405908703470223627112807", 10)
	priv.D.SetString("13831182946327257485202449917886310014691411920799402330358005079372340226830908854069199366514998264673001296173426027428444253967202583807506055301970836598801986293823265732114538686262348955810487418780437827682192815159449445514995549123253708563738091263420720573494911415046501191793781946792358121675854595191396101396382587442882935489858060385461971664771858075315050803868636800573416034338516755974135293658834448940549284239795621310918325574568182905526946604653505127579763211271140295994151861675935967787208484255187831364945358888205056068887846318281877223185543644778354964586968082185382499560369", 10)
	priv.Primes[0].SetString("178543263971563445611846753647960454328877138110494552805342946372410027118203982039511174780961824855984433336212442651027464024789151422760784357833919112679849875175290866326856420160636005838393018472572662993504365089058201870664786291964784723445519174387159504797796942043782152797738931277870772462409", 10)
	priv.Primes[1].SetString("161290608076779279684432358029784616172585842112589351628730355733876482119583845522812629523767500848816306923105072613282149253767315567637739875378081888629173569299624561645978174853005648841950258779154997443239884879774661727133962280797487609122726047048985176827535144336292828924682552883542838648623", 10)

	priv.Precompute()

	testsdp := "v=0\r\no= 0 0   \r\ns=\r\na=group:BUNDLE video audio\r\nm=video 9 UDP/TLS/RTP/SAVPF 102\r\nc=IN IP4 0.0.0.0\r\na=setup:active\r\na=mid:video\r\na=ice-ufrag\r\na=ice-pwd\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:102 H264/90000\r\na=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\na=sendonly\r\na=fingerprint:sha-256 34:1F:E5:AD:AC:79:55:8E:80:38:A5:57:EF:75:34:EA:F5:22:A4:DB:E2:5D:82:67:C5:15:A3:FA:B5:E9:B8:0B\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=setup:active\r\na=mid:audio\r\na=ice-ufrag\r\na=ice-pwd\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\na=sendonly\r\na=fingerprint:sha-256 34:1F:E5:AD:AC:79:55:8E:80:38:A5:57:EF:75:34:EA:F5:22:A4:DB:E2:5D:82:67:C5:15:A3:FA:B5:E9:B8:0B\r\n"

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
	}

	r := rand.New(rand.NewSource(2020))
	certBytes, err := x509.CreateCertificate(r, template, template, &priv.PublicKey, priv)
	assert.Equal(t, nil, err)

	cert, err := x509.ParseCertificate(certBytes)

	assert.Equal(t, nil, err)

	s := &sdp.SessionDescription{}
	media := []mediaSection{
		{
			id: "video",
			transceivers: []*RTPTransceiver{{
				kind: RTPCodecTypeVideo,
			}},
			data: false,
		},
		{
			id: "audio",
			transceivers: []*RTPTransceiver{{
				kind: RTPCodecTypeAudio,
			}},
			data: false,
		},
	}

	for i := 0; i < 2; i++ {
		media[i].transceivers[0].setSender(&RTPSender{})
		media[i].transceivers[0].setDirection(RTPTransceiverDirectionSendonly)
	}

	s, err = populateSDP(s, false,
		&Certificate{
			privateKey: priv,
			x509Cert:   cert,
		},
		false, engine, sdp.ConnectionRoleActive, []ICECandidate{}, ICEParameters{}, media, ICEGatheringStateNew)

	assert.Equal(t, nil, err)

	sdparray, err := s.Marshal()

	assert.Equal(t, nil, err)

	assert.Equal(t, testsdp, string(sdparray))
}
