use crate::names::DnsNameExtractor;

#[derive(Debug, Default)]
pub struct DnsHeader {
    pub xid: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn write(&self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn std::error::Error>> {
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
        Ok(std::mem::size_of::<DnsHeader>())
    }

    /// Return the (header, bytes_consumed) to make it easier to adv a parser
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return Err("Not enough data to parse a DNS header".into());
        }

        //println!("BYTES: {:?}", &bytes);
        let mut this = Self::default();
        this.xid = u16::from_be_bytes(bytes[0..2].try_into().expect("slice is checked"));
        this.flags = u16::from_be_bytes(bytes[2..4].try_into().expect("slice is checked"));
        this.qdcount = u16::from_be_bytes(bytes[4..6].try_into().expect("slice is checked"));
        this.ancount = u16::from_be_bytes(bytes[6..8].try_into().expect("slice is checked"));
        this.nscount = u16::from_be_bytes(bytes[8..10].try_into().expect("slice is checked"));
        this.arcount = u16::from_be_bytes(bytes[10..12].try_into().expect("slice is checked"));

        Ok((this, std::mem::size_of::<Self>()))
    }

    pub fn debug_flags(&self) {
        if self.flags & 0xF == 0 {
            println!("DnsHeader: Is a response");
        } else {
            println!("DnsHeader: Is a question");
        }
    }
}

#[derive(Debug)]
pub enum DnsRec<'a> {
    Ipv4(DnsIpv4),
    Ipv6(DnsIpv6),
    Soa(DnsSoa),
    Mx(DnsMx),
    Other(DnsRecord<'a>),
}

#[derive(Debug)]
pub struct DnsRecord<'a> {
    pub compression: u16,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub length: u16,
    pub rdata: Vec<u8>,
    pub name_extractor: DnsNameExtractor<'a>,
}

impl<'a> DnsRecord<'a> {
    pub fn from_bytes(
        bytes: &'a [u8],
        name_extractor: DnsNameExtractor<'a>,
    ) -> Result<(DnsRecord<'a>, usize), Box<dyn std::error::Error>> {
        if bytes.len() < 12 {
            return Err("Not enough data to parse a DNS record".into());
        }
        //println!("PARSING BYTES: {:?}", bytes);
        let compression =
            u16::from_be_bytes(bytes[0..2].try_into().expect("slice is checked")) << 2 >> 2;
        let record_type = u16::from_be_bytes(bytes[2..4].try_into().expect("slice is checked"));
        let class = u16::from_be_bytes(bytes[4..6].try_into().expect("slice is checked"));
        let ttl = u32::from_be_bytes(bytes[6..10].try_into().expect("slice is checked"));
        let length = u16::from_be_bytes(bytes[10..12].try_into().expect("slice is checked"));
        let bytes_read = 12 + length as usize;
        let rdata: Vec<u8> = bytes[12..bytes_read].into();

        Ok((
            Self {
                compression,
                record_type,
                class,
                ttl,
                length,
                rdata,
                name_extractor,
            },
            bytes_read,
        ))
    }

    pub fn parse_bytes(
        bytes: &'a [u8],
        name_extractor: DnsNameExtractor<'a>,
    ) -> Result<(DnsRec<'a>, usize), Box<dyn std::error::Error>> {
        let (record, offset) = Self::from_bytes(bytes, name_extractor)?;

        Ok((
            match record.record_type {
                1 => DnsRec::Ipv4(record.into()),
                6 => DnsRec::Soa(record.into()),
                15 => DnsRec::Mx(record.into()),
                28 => DnsRec::Ipv6(record.into()),
                _ => DnsRec::Other(record),
            },
            offset,
        ))
    }
}

#[derive(Debug)]
pub struct DnsSoa {
    pub compression: u16,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub length: u16,
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
}

impl From<DnsRecord<'_>> for DnsSoa {
    fn from(r: DnsRecord) -> DnsSoa {
        let mut offset = 0;
        let (mname, bytes_consumed) = r
            .name_extractor
            .parse_from_buffer(&r.rdata[offset..])
            .unwrap();
        offset += bytes_consumed;
        let (rname, bytes_consumed) = r
            .name_extractor
            .parse_from_buffer(&r.rdata[offset..])
            .unwrap();
        offset += bytes_consumed;

        let bytes = r.rdata;

        let serial = u32::from_be_bytes(
            bytes[offset..(offset + 4)]
                .try_into()
                .expect("slice is checked"),
        );
        offset += 4;
        let refresh = u32::from_be_bytes(
            bytes[offset..(offset + 4)]
                .try_into()
                .expect("slice is checked"),
        );
        offset += 4;
        let retry = u32::from_be_bytes(
            bytes[offset..(offset + 4)]
                .try_into()
                .expect("slice is checked"),
        );
        offset += 4;
        let expire = u32::from_be_bytes(
            bytes[offset..(offset + 4)]
                .try_into()
                .expect("slice is checked"),
        );

        DnsSoa {
            compression: r.compression,
            record_type: r.record_type,
            class: r.class,
            ttl: r.ttl,
            length: r.length,
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
        }
    }
}

#[derive(Debug)]
pub struct DnsMx {
    pub compression: u16,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub length: u16,
    pub preference: u16,
    pub exchange: String,
}

impl From<DnsRecord<'_>> for DnsMx {
    fn from(r: DnsRecord) -> DnsMx {
        let (exchange, _bytes_consumed) = r
            .name_extractor
            .parse_from_buffer(&r.rdata[2..r.rdata.len()])
            .unwrap();

        DnsMx {
            compression: r.compression,
            record_type: r.record_type,
            class: r.class,
            ttl: r.ttl,
            length: r.length,
            preference: u16::from_be_bytes(r.rdata[0..2].try_into().expect("slice is checked")),
            //exchange: "TBD".to_string(),
            exchange,
        }
    }
}

#[derive(Debug)]
pub struct DnsIpv6 {
    pub compression: u16,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub length: u16,
    pub address: std::net::Ipv6Addr,
}

impl From<DnsRecord<'_>> for DnsIpv6 {
    fn from(r: DnsRecord) -> DnsIpv6 {
        DnsIpv6 {
            compression: r.compression,
            record_type: r.record_type,
            class: r.class,
            ttl: r.ttl,
            length: r.length,
            address: std::net::Ipv6Addr::from(
                <&[u8] as TryInto<[u8; 16]>>::try_into(&r.rdata).unwrap(),
            ),
        }
    }
}

#[derive(Debug)]
pub struct DnsIpv4 {
    pub compression: u16,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub length: u16,
    pub address: std::net::Ipv4Addr,
}

impl From<DnsRecord<'_>> for DnsIpv4 {
    fn from(r: DnsRecord) -> DnsIpv4 {
        DnsIpv4 {
            compression: r.compression,
            record_type: r.record_type,
            class: r.class,
            ttl: r.ttl,
            length: r.length,
            address: std::net::Ipv4Addr::from(
                <&[u8] as TryInto<[u8; 4]>>::try_into(&r.rdata).unwrap(),
            ),
        }
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub name: String,
    pub dnstype: u16,
    pub dnsclass: u16,
}

impl DnsQuestion {
    fn hostname_to_packet(&self) -> String {
        let mut s = String::with_capacity(self.name.len() + 1);

        for chunk in self.name.split(".") {
            s.push(char::from_u32(chunk.len() as u32).expect("safe downcast"));
            s.push_str(chunk);
        }

        s
    }

    pub fn estimate_size(&self) -> usize {
        // +2 because: extra null char and extra prefixed size byte
        self.name.len() + 2 + std::mem::size_of::<u16>() + std::mem::size_of::<u16>()
    }

    pub fn write(&self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn std::error::Error>> {
        let hostname = self.hostname_to_packet();

        buf.extend_from_slice(&hostname.as_bytes());
        buf.push(0_u8);
        buf.extend_from_slice(&self.dnstype.to_be_bytes());
        buf.extend_from_slice(&self.dnsclass.to_be_bytes());

        Ok(self.estimate_size())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        //        println!("Q?esize: {}", std::mem::size_of::<Self>());
        //        if bytes.len() < std::mem::size_of::<Self>() {
        //            return Err("Not enough data to parse a DNS question".into());
        //        }

        let name = std::ffi::CStr::from_bytes_until_nul(bytes)?.to_str()?;
        let offset = name.len() + 1;
        let dnstype = u16::from_be_bytes(
            bytes[offset..(offset + 2)]
                .try_into()
                .expect("slice is checked"),
        );
        let offset = offset + 2;
        let dnsclass = u16::from_be_bytes(
            bytes[offset..(offset + 2)]
                .try_into()
                .expect("slice is checked"),
        );

        Ok((
            DnsQuestion {
                name: parse_dns_str_to_string(name)?,
                dnstype,
                dnsclass,
            },
            offset + 2,
        ))
    }
}

fn parse_dns_str_to_string(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut result = String::new();
    let mut read_n = 0;
    for c in s.chars() {
        if read_n == 0 {
            read_n = c as usize;
        } else {
            result.push(c);
            read_n -= 1;

            if read_n == 0 {
                result.push('.');
            }
        }
    }
    Ok(result)
}
