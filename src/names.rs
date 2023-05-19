#[derive(Debug, Clone)]
pub struct DnsNameExtractor<'a> {
    pub bytes: &'a [u8],
}

impl DnsNameExtractor<'_> {
    // The compression scheme allows a domain name in a message to be
    // represented as either:
    //
    // - a sequence of labels ending in a zero octet
    // - a pointer
    // - a sequence of labels ending with a pointer
    //
    // returns (name, bytes_used_of_buf)
    pub fn parse_from_buffer(
        &self,
        buf: &[u8],
    ) -> Result<(String, usize), Box<dyn std::error::Error>> {
        let mut result = String::new();

        let mut n_in_label = 0;
        let mut bytes_consumed = 0;
        for (idx, c) in buf.iter().enumerate() {
            bytes_consumed += 1;
            if n_in_label == 0 {
                n_in_label = *c as usize;

                if result.len() > 0 {
                    result.push('.');
                }
                if *c == 0 {
                    break;
                }

                // If we detect a pointer where the first two bits are 11XXXX.
                // We can also use 63 (max label size) to detect.
                // If so, then we should parse the pointer, merge the result, and break.
                if n_in_label > 63 {
                    // Drop the two first bits to get the true index.
                    let ptr =
                        u16::from_be_bytes(buf[idx..idx + 2].try_into().expect("slice is checked"));
                    let index_of_pointer = (ptr << 2 >> 2) as usize;

                    // We're consuming an extra byte for the u16 ptr.
                    bytes_consumed += 1;
                    //                    println!(
                    //                        "ptr: {:#018b}, index: {index_of_pointer}, res: {:?}",
                    //                        ptr, &result
                    //                    );
                    // We can ignore bytes consumed here because these are consumed from the
                    // response buffer (not some smaller rdata buffer).
                    let (s, _consumed) = self.parse_from_buffer(&self.bytes[index_of_pointer..])?;
                    result.push_str(s.as_str());
                    break;
                }
            } else {
                result.push(*c as char);
                n_in_label -= 1;
            }
        }

        Ok((result, bytes_consumed))
    }
}
