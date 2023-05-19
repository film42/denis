use crate::names::DnsNameExtractor;
use crate::proto::*;
use std::net::UdpSocket;

mod names;
mod proto;

struct DnsResponse;

struct DnsRequest {
    name: String,
    request_type: String,
}

impl DnsRequest {
    fn build(name: String) -> Self {
        Self {
            name,
            request_type: "A".into(),
        }
    }

    fn request_type(self, request_type: String) -> Self {
        Self {
            request_type,
            ..self
        }
    }

    fn resolve(self) -> Result<DnsResponse, Box<dyn std::error::Error>> {
        let req_type = match self.request_type.as_str() {
            "A" => 1,
            "SOA" => 6,
            "MX" => 15,
            "AAAA" => 28,
            _ => {
                return Err(format!(
                    "Unknown req type for the moment {} to an enum number",
                    &self.request_type
                )
                .into());
            }
        };

        let header = DnsHeader {
            // TODO: Random XID when I have internet again.
            xid: 1337_u16,
            flags: 0x0100_u16, // Q=0, RD=1
            qdcount: 1_u16,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let question = DnsQuestion {
            name: self.name.clone(),
            dnstype: req_type,
            dnsclass: 1_u16,
        };

        let mut p: Vec<u8> =
            Vec::with_capacity(std::mem::size_of::<DnsHeader>() + question.estimate_size());

        header.write(&mut p)?;
        question.write(&mut p)?;

        //        DnsQuestion {
        //            name: "mx.com",
        //            dnstype: 1_u16,
        //            dnsclass: 1_u16,
        //        }
        //        .write(&mut p)?;

        //        println!(
        //            "HEADER: {:?}, QUESTION: {:?}, BUFFER: {:?}",
        //            &header, &question, &p
        //        );

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("10.26.129.123:53")?;

        // println!("Read timeout: {:?}", socket.read_timeout());

        let b = socket.send(&p)?;

        println!("Wrote {:?} bytes to UDP server", &b);

        let mut res: Vec<u8> = vec![];
        res.resize(8096, 0);

        let b = socket.recv(&mut res)?;

        let name_extractor = DnsNameExtractor { bytes: &res[0..b] };

        let (header, skip) = DnsHeader::from_bytes(&res[0..b])?;
        header.debug_flags();
        let mut offset = skip;

        println!("Question count: {}", &header.qdcount);
        //        println!(
        //            "BYTES: (LEN {}) {:?}",
        //            &res[offset..b].len(),
        //            &res[offset..b]
        //        );
        for _ in 0..(header.qdcount) {
            let (question, skip) = DnsQuestion::from_bytes(&res[offset..b])?;
            println!("Question: {:?}", &question);
            offset = offset + skip;
        }

        println!("Response Header: {:?}", &header);

        println!("Answer count: {}", &header.ancount);
        for _ in 0..(header.ancount) {
            //println!("BUYTES: {:?}", &res[offset..b]);
            let (record, skip) = DnsRecord::parse_bytes(&res[offset..b], name_extractor.clone())?;
            offset = offset + skip;

            println!("ANSWER: {:?}", &record);
        }
        println!("NS count: {}", &header.nscount);
        for _ in 0..(header.nscount) {
            let (record, skip) = DnsRecord::parse_bytes(&res[offset..b], name_extractor.clone())?;
            offset = offset + skip;

            println!("NS: {:?}", &record);
        }
        println!("Add rec count: {}", &header.arcount);
        for _ in 0..(header.arcount) {
            let (record, skip) = DnsRecord::parse_bytes(&res[offset..b], name_extractor.clone())?;
            offset = offset + skip;

            println!("AR: {:?}", &record);
        }

        Ok(DnsResponse)
    }
}

fn main() {
    let mut args = std::env::args();

    let _bin_name = args.next().unwrap();

    let request_type = args
        .next()
        .expect("should have specified a valid request type: A, MX, etc");
    let domain_name = args.next().expect("should have specified a domain name");
    //DnsRequest("googlemail.com").resolve().unwrap();
    DnsRequest::build(domain_name)
        .request_type(request_type)
        .resolve()
        .unwrap();
}
