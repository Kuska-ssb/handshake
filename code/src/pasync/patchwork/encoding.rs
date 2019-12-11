use async_std::io;
use serde_json::Value;
use sodiumoxide::crypto::hash::sha256;

use crate::pasync::util::to_ioerr;


/*

pub fn ssb_sha256(v: &Value) -> Result<sha256::Digest, io::Error> {
    let stringified  = stringify_json(&v)?;
    let utf16 : Vec<u16> = stringified.encode_utf16().collect();
    if utf16.iter().any(|ch_u16| *ch_u16 > 0xff) {
        let v8enc = utf16.iter().map(|ch_u16| (ch_u16 & 0xff) as u8)
            .collect::<Vec<u8>>();
        Ok(sha256::hash(&v8enc[..]))
    } else {
        Ok(sha256::hash(&stringified.as_bytes()[..]))
    }
}

*/

pub fn ssb_sha256(v: &Value) -> Result<sha256::Digest, io::Error> {
    let v8encoding = stringify_json(&v)?
        .encode_utf16()
        .map(|ch_u16| (ch_u16 & 0xff) as u8)
        .collect::<Vec<u8>>();

    Ok(sha256::hash(&v8encoding[..]))
}

pub fn stringify_json(v: &Value) -> Result<String, io::Error> {
    fn spaces(n: usize) -> &'static str {
        &"                                         "[..2 * n]
    }
    // see https://www.ecma-international.org/ecma-262/6.0/#sec-serializejsonobject
    fn append_json(buffer: &mut String, level: usize, v: &Value) -> Result<(), io::Error> {
        match v {
            Value::Object(values) => {
                if values.is_empty() {
                    buffer.push_str("{}");
                } else {
                    buffer.push_str("{\n");
                    for (i, (key, value)) in values.iter().enumerate() {
                        buffer.push_str(spaces(level + 1));
                        buffer.push_str(&serde_json::to_string(&key).map_err(to_ioerr)?);
                        buffer.push_str(": ");
                        append_json(buffer, level + 1, &value)?;
                        if i < values.len() - 1 {
                            buffer.push(',');
                        }
                        buffer.push('\n');
                    }
                    buffer.push_str(spaces(level));
                    buffer.push('}');
                }
            }
            Value::Array(values) => {
                if values.is_empty() {
                    buffer.push_str("[]");
                } else {
                    buffer.push_str("[\n");
                    for (i, value) in values.iter().enumerate() {
                        buffer.push_str(spaces(level + 1));
                        append_json(buffer, level + 1, &value)?;
                        if i < values.len() - 1 {
                            buffer.push(',');
                        }
                        buffer.push('\n');
                    }
                    buffer.push_str(spaces(level));
                    buffer.push(']');
                }
            }
            Value::String(value) => {
                buffer.push_str(&serde_json::to_string(&value).map_err(to_ioerr)?);
            }
            Value::Number(value) => {
                buffer.push_str(&value.to_string());
            }
            Value::Bool(value) => {
                buffer.push_str(if *value { "true" } else { "false" });
            }
            Value::Null => {
                buffer.push_str("null");
            }
        }
        Ok(())
    }
    let mut result = String::new();
    append_json(&mut result, 0, &v)?;
    Ok(result)
}

mod test {
    use super::*;

    const JSON : &str = r#"{"a":0,"b":1.1,"c":null,"d":true,"f":false,"g":{},"h":{"h1":1},"i":[],"j":[1],"k":[1,2]}"#;
    #[test]
    fn test_json_stringify() -> Result<(), io::Error> {
        let v: Value = serde_json::from_str(JSON).map_err(to_ioerr)?;
        let json = stringify_json(&v)?;
        let expected = r#"{
  "a": 0,
  "b": 1.1,
  "c": null,
  "d": true,
  "f": false,
  "g": {},
  "h": {
    "h1": 1
  },
  "i": [],
  "j": [
    1
  ],
  "k": [
    1,
    2
  ]
}"#;

        assert_eq!(expected, json);
        Ok(())
    }
    #[test]
    fn test_verify_known_msg_integrity() -> Result<(), io::Error> {
        let expected = "Cg0ZpZ8cV85G8UIIropgBOvM8+Srlv9LSGDNGnpdK44";
        let message = r#"{"previous":"%seUEAo7PTyA7vNwnOrmGIsUFfpyRzOvzGVv1QCb/Fz8=.sha256","author":"@BIbVppzlrNiRJogxDYz3glUS7G4s4D4NiXiPEAEzxdE=.ed25519","sequence":37,"timestamp":1439392020612,"hash":"sha256","content":{"type":"post","text":"@paul real time replies didn't work.","repliesTo":"%xWKunF6nXD7XMC+D4cjwDMZWmBnmRu69w9T25iLNa1Q=.sha256","mentions":["%7UKRfZb2u8al4tYWHqM55R9xpE/KKVh9U0M6BdugGt4=.sha256"],"recps":[{"link":"@hxGxqPrplLjRG2vtjQL87abX4QKqeLgCwQpS730nNwE=.ed25519","name":"paul"}]},"signature":"gGxSPdBJZxp6x5f3HzQGoQSeSdh/C5AtymIn+miWa+lcC6DdqpRSgaeH9KHeLf+/CKhU6REYIpWaLr4CKDMfCg==.sig.ed25519"}"#;
        let message_value: Value = serde_json::from_str(&message)?;
        let current = base64::encode(&ssb_sha256(&message_value)?);
        assert_eq!(expected, current);
        Ok(())
    }
}

/*
Messages that key does not match

*{"key":"%dzoDoZ2oloAjslyGw/RU+78QaoeOZpmh5C9P9SRwd+k=.sha256","value":{"previous":"%VQWg91Vk+ZpVI8FsTLYC32QeDk3U2ocE4jQTmXryTos=.sha256","author":"@SdLEo92w3LBL2yni6AXOf2XoW4arjnKvVw4Y/078r98=.ed25519","sequence":6,"timestamp":1477527012919,"hash":"sha256","content":{"overview":"ARQGARgBBhQBCw4BEgcBFQUBGQEJJRsYGBsiEw8hFBAVEBcYGx8VCyIVFCUiFRgbHRESHxkKHw8QHhocExEZGhkaLA8gGRsWERgYEB0QDSEaFR0RFhobEDAOHh4XHxAUGRMYDRIfGxMlEA4jFBUoEQMIFxkTDyATExMQFxgbIRMKJhEUJiEVFxwcEBIgGg0bDxMbGxwSER4WGBsrDh8aGxURGBgQHREOIBkYGREXGhsSMAoeHxYeEBUZExgMEiAbFSMQECAUFSs=","duration":106.71000000000001,"fileName":"u burundi serious.webm","fallbackFileName":"u burundi serious.mp3","type":"ferment/audio","title":"u burundi serious","description":"","audioSrc":"magnet:?xt=urn:btih:0900315fa27a918e6426658755dc4085616afcdc&dn=u+burundi+serious&tr=ws%3A%2F%2Fpub.ferment.audio%3A43770","artworkSrc":"blobstore:&i3L3p47osvPxkQLKFHxp/O04C1ZaZ2WDwk5JJ2SW/9w=.sha256"},"signature":"rdpQDmt1xUkW/J3yM81Jzz5ddyiNmgH6JkbNlLFpSNdvwoX94zWHewi8ZGyXUFrIIawPbFPImDbGHV0s59JJCA==.sig.ed25519"},"timestamp":1573921730206.004,"rts":1477527012919}
*{"key":"%RUcldndjJUkEcZ5hX6zAj/xLlnh0n4BZ6ThJOW5RvIk=.sha256","value":{"previous":"%gbem82xZNVHbOM2pyOlxymsAfstdMFfGSoawWQtObX8=.sha256","author":"@TXKFQehlyoSn8UJAIVP/k2BjFINC591MlBC2e2d24mA=.ed25519","sequence":1557,"timestamp":1495245157893,"hash":"sha256","content":{"type":"post","transactionHash":9.691449834862513e+76,"address":7.073631810716965e+46,"event":"ActionAdded","text":"{\"actionID\":\"1\",\"amount\":\"0\",\"description\":\"Bind Ethereum events to Secure Scuttlebutt posts\"}}"},"signature":"/Qvm9ozEfl0Thyvs+mnwhLDReZ8xeKXA3hSXOxm53SFkLEnnJ+IF0l7LSqc56Y3vl8FwarJ6k0PGmcU3U8FMAw==.sig.ed25519"},"timestamp":1572522853237.001,"rts":1495245157893}
*{"key":"%qDNheCV+SoaAhicwzMvm9VPnrTAHWwHH2HFeWIRQ7is=.sha256","value":{"previous":"%OuoWKhQIZZ3ZizqqwS+/fZdhbE8tgVhcgDCWci8Es7c=.sha256","author":"@D26sJ/Seyc4WBcpZDi4PYcqEg+2nUb7WoTQg9NknDyg=.ed25519","sequence":1156,"timestamp":1493771736542,"hash":"sha256","content":{"id":"d1fc6342-54b8-4650-9cb9-c89ff5617ab2","class":"com.icecondor.nest.db.activity.GpsLocation","date":"2017-05-03T00:35:36.238Z","type":"location","latitude":45.448031,"longitude":-122.6440624,"accuracy":21.320999145507812,"provider":"network"},"signature":"xgf4TRL7G0cyTMgh+RmdmC/gKjnS/LkqdHoox/Cpk/4EMk4kY4VqleOC4h0/Cpz8B8nqX0q6dEu4lN/sHv6mBQ==.sig.ed25519"},"timestamp":1573951202521.001,"rts":1493771736542}
*{"key":"%bWK1Vcx8/4DS4RvYuzUEN5CcU8zIDK/Amkh7NMpvqoQ=.sha256","value":{"previous":"%vEi16xARnGoAdPd1vuLHeXMH8n5zp4QLZpgCnidmImk=.sha256","author":"@D26sJ/Seyc4WBcpZDi4PYcqEg+2nUb7WoTQg9NknDyg=.ed25519","sequence":1160,"timestamp":1493772052185,"hash":"sha256","content":{"id":"5ba3690b-7f33-427e-9228-d1a98601149c","class":"com.icecondor.nest.db.activity.GpsLocation","date":"2017-05-03T00:40:51.849Z","type":"location","latitude":45.448031,"longitude":-122.6440624,"accuracy":21.267000198364258,"provider":"network"},"signature":"5KKq2dJV9Q0WZ7bgejoURSsKmsI5DB37GsJm3PlpR9gIC3Rq+1QS+85hG+CYmSbPFv525r4rCORyaMsiMFaqCw==.sig.ed25519"},"timestamp":1573951203518,"rts":1493772052185}
*{"key":"%xVgZcvVzh2M0x7si4wRB6XMeNKc0AzCfDTIg+E/RG6M=.sha256","value":{"previous":"%+uynFIOfsYkq4KcRImpBnV49+bpG3ovh1Gd2TN+bgh0=.sha256","sequence":11429,"author":"@NeB4q4Hy9IiMxs5L08oevEhivxW+/aDu/s/0SkNayi0=.ed25519","timestamp":1537570152250.0059,"hash":"sha256","content":{"type":"tag","version":1,"tagged":true,"message":"%jTL7v2H34mnxbCxvJyZ91Ln8cnRV3CpTfPTCs4Onqxs=.sha256","root":"%esqfvTutF+iAHGMGHgIpTmIAZfxEIkjw3fhV/TE+nVY=.sha256","branch":[]},"signature":"/d+quXCaz+VckfW2281NuRvFBj4lkxrjbgsCuRaURJLMJIRdczkQW8na1JhJJ+PvLOpN4D8NMJMNaMILAafdDg==.sig.ed25519"},"timestamp":1572523914210.0176,"rts":1537570152250.0059}
*{"key":"%uOHE2ol29sMLCqv32S/oFgYCcIoiZFuHT/zzmoTGyy0=.sha256","value":{"previous":"%wqIJKGIE5KrEpLuJ8TVfbLC/z5xxz3Ig24cniT3x554=.sha256","sequence":180,"author":"@GOl+398b2kWeLi6+DCcU0i3AWD6vWmUtocBVYbpkpNk=.ed25519","timestamp":1538442187303.0059,"hash":"sha256","content":{"type":"tag","version":1,"tagged":true,"message":"%zv56AbEcR1+XKcOF3E7J+HNoKrxsd+0MQ/eVPQanfb8=.sha256","root":"%xUr5JEinK8EdxcC6aLkV6iGM2yxygYtYUzhZf1KCSi8=.sha256","branch":[]},"signature":"zmDc4WW1Ml3aEWHPiYLszT9G2Qo9+rYU49XnVqdP5DOTMtndiMI9o3vRrSLqy7IKcoE/mr+HQGTRSiX1IEBpBw==.sig.ed25519"},"timestamp":1573741494913.001,"rts":1538442187303.0059}
*{"key":"%wFgV3SgE0DLxkpPbtdPBVDVkqCSS9sBQfkavwiYRsoA=.sha256","value":{"previous":"%Vf9J3C14VxurHMuVQoUAgLKzGZsgwbEUoCe32bNC4Aw=.sha256","sequence":26,"author":"@99/W1Xn0r+q/fDweDqoUGfIb+mT9TVL1Ey3gwuefId4=.ed25519","timestamp":1539407727679.0059,"hash":"sha256","content":{"type":"item","text":"{\"type\":\"ADD_FILE\",\"data\":{\"name\":\"GroundedFancyInchworm\",\"hash\":\"QmPwLyj853dfE64XeLN6i8pPr57jyYpewpuwHiNimWQwML\",\"size\":13175545,\"mime\":\"video/webm\",\"ext\":\"webm\"}}"},"signature":"/E7Szpk5/U7fJVx+PDiv05LnzRRl3t3EP//RGUtA2nE8C2BZbcXAYhxMrIx/wK5skwXkOQcIJ3OPMBibx3wjBA==.sig.ed25519"},"timestamp":1574091510661.004,"rts":1539407727679.0059}
*{"key":"%m1IszUizZ9biID6Vx2xBpnEmg6SW2GzT4PrDnrO67mE=.sha256","value":{"previous":"%oNsjPCK6WGLbSeUhK+KAWY7+KoU1xYHPkNQToXlBne4=.sha256","sequence":61,"author":"@N7zS2DdbEaqDuaHrI9tv/PJabJPgy7FWPILu5sNIkAQ=.ed25519","timestamp":1542381276195.0059,"hash":"sha256","content":{"type":"tag","version":1,"tagged":true,"message":"%6NrsE7Wia6NMtSR20dJBIAC+Nt7VeyNfuTRVGqvyS28=.sha256","root":"%9ND6VqQDBY6nE6KF6YKXZfirBTVL0x5ley94obX4XmM=.sha256","branch":[]},"signature":"8/MxipRi7Xq6VRsmJNxZnKbdAjhUky3kmER1OaX4rEqdTyue6KDLg2eAhd3Z0QtGNmvyHh2DYre4zM3s7ljFDA==.sig.ed25519"}
*{"key":"%ToQyaBeMhJRAG4ijxzqpNXuyj6Tp4zwEj6uSo7V7VGA=.sha256","value":{"previous":"%Sn275VHP81N2zguhonIYPqqVfJqsMQfEbCyILgnzrFI=.sha256","sequence":26,"author":"@L2IRT3qfHwAf8Yym1HWS8LFCEVxBD28PtmYNcmE2ep8=.ed25519","timestamp":1544154094040.0059,"hash":"sha256","content":{"type":"about","about":"%M54MjF97/GVC76IZ8p0uQOZdK3rWHjpxUDfNYF5R3/0=.sha256","name":"earthfirst"},"signature":"Gyclna0puCknFGVybAZUTDz0D8PNgRNvxPL3wXuDmBNVzf/7oleFTnVkrOJyB3hdmdW5opIeZka0JRh4uGsvBA==.sig.ed25519"},"timestamp":1574091521497.002,"rts":1544154094040.0059}
*{"key":"%9Z6qEK7UPmEl/qVDNdVLz0WVBxY7leSmPg5CKAaXwGw=.sha256","value":{"previous":"%eLPo5nbOFElsWkTjf83ufIZ/MNUTf0WuyMVn5nTC0k8=.sha256","sequence":40,"author":"@L2IRT3qfHwAf8Yym1HWS8LFCEVxBD28PtmYNcmE2ep8=.ed25519","timestamp":1544154094054.0059,"hash":"sha256","content":{"type":"tag","version":1,"tagged":true,"message":"%NVWzCZg8tzpgwByQVG2bU4lXkeHqIeWUVIZJhcWDUVQ=.sha256","root":"%M54MjF97/GVC76IZ8p0uQOZdK3rWHjpxUDfNYF5R3/0=.sha256","branch":[]},"signature":"WlnakDbUPuAjc/PyVfhB+z4RuVXS4t8nVfyPXbSFw0OwVy5ROVC944CZNTg8joJhN13jgcUQ/+BYTcS7lFnLBA==.sig.ed25519"},"timestamp":1574091545994.005,"rts":1544154094054.0059}
*{"key":"%FXtp7TYCHDgdLWOKKGY24tAXyIeDmjjCzLJvyx1Adv0=.sha256","value":{"previous":"%2FCTBYyVUxYrUkNrhevP5cJCyQmzLIA+uKzneJ540W0=.sha256","sequence":303,"author":"@WplgA4skTYTDSY26QQMcctgL6Tle3Ol0LOznFCNkwxQ=.ed25519","timestamp":1545572514041.0059,"hash":"sha256","content":{"type":"tag","version":1},"signature":"ypF7MIwvEQOjDqbmK2955Py2MPvN9sFIzr0VNe8BqPPqP+aOBR7k6vKc/vkIyRKPzIaAewZNXGDt6sxIHRYSBA==.sig.ed25519"},"timestamp":1574091710747,"rts":1545572514041.0059}
*{"key":"%sl5JSCdyIxJrqKlu0OCL66005CWOsjN/ADgL1dXoTv0=.sha256","value":{"previous":"%N1uNs+2/sbDKtD07y99j1umoQM8G3m508Gi7BdHyf5k=.sha256","sequence":42,"author":"@RFojz2yhFyImgy4Ycpl2xmWc0Ms2QPUVHqkEGqkhtC4=.ed25519","timestamp":1545745150355.0059,"hash":"sha256","content":{"type":"poll","details":{"choices":["2018-12-28T11:00:00.000Z","2018-12-29T11:00:00.000Z","2018-12-30T11:00:00.000Z","2018-12-31T11:00:00.000Z"],"type":"meetingTime"},"title":"Test","closesAt":"2018-12-28T04:00:00.000Z","version":"v1","mentions":[]},"signature":"PnoBTzWU85Q+vX/uPb29ZimF/kpyv0oScAlUQy/xXVaOT2UVTjFFPS0IUl83yYIDOxRpmurmO72xxK9k28X4Dg==.sig.ed25519"},"timestamp":1574091556458.005,"rts":1545745150355.0059}
*{"key":"%BTaRh01ReFKZBd1Pci06vHJ+tlWWYLlQj0IkHIgiCX0=.sha256","value":{"previous":"%weTTvcPEBdD0rK1DHbJe28JXxhdVZU0Hh1kThdl8bL0=.sha256","sequence":106,"author":"@/liDKYile8eb+0BCFSEO/13ANao13A1JUy7BOSSU7xs=.ed25519","timestamp":1546485101483.0059,"hash":"sha256","content":{"type":"tag","version":1,"tagged":true,"message":"%mWlQC9rk62eWVDnVdUQLA6RcX71IP/uYKr17QhFyNgI=.sha256","root":"%AocvUXfwTn5hkVwMVkSzj7mtPSN1lP4ZZHMmA7Y0s4o=.sha256","branch":[]},"signature":"ypaop0NtrFjnmF9PLHUua1r4MyNGFYQIDJQTRkiFGC/vgtYV7uJO3466i6kPwucnAg+VQko+9dZAcWap29B3CQ==.sig.ed25519"},"timestamp":1573921806351.005,"rts":1546485101483.0059}
{"key":"%GsvUj1gEvLjg0U1p7WW6PxHqXFNq4YwEOIR/YQZg97w=.sha256","value":{"previous":"%fnaufw0dA0CgWT0A+Bskb3E14Rgs/LLUWGMuOSRkqWM=.sha256","sequence":819,"author":"@EYSiJyB/NHHQhgJdwOgiHJE4Az2/vnYo5DP3m67cvt8=.ed25519","timestamp":1548010388796.0059,"hash":"sha256","content":{"type":"tag","version":1,"tagged":true,"message":"%GGiHPFghf6FNd5Ev12AtpmiiZWtE0qA1H84QotLdRKc=.sha256","root":"%32aIXax/ePTcFTbFBGoXpWALw52qmK8t+t/rMQIdtjY=.sha256","branch":[]},"signature":"BIif4OCEZ2P5rXh3YJn64Isy5JP4CcX+waKW9hcPUhzY7TpdoC39f1vwNrWXFkT9kbKUht5jE3YBZeinczAUDA==.sig.ed25519"},"timestamp":1574091748834.001,"rts":1548010388796.0059}
*/
