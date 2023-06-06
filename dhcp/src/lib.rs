#![no_std]

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

pub const DHCP_MAGIC_NUMBER: u32 = 0x63825363;

pub const BROADCAST: u32 = 0b1000_0000_0000_0000;

/// The possible opcodes of a DHCP packet.
#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Request = 1,
    Reply = 2,
}

/// The possible message types of a DHCP packet.
#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    pub const fn opcode(&self) -> OpCode {
        match *self {
            MessageType::Discover
            | MessageType::Inform
            | MessageType::Request
            | MessageType::Decline
            | MessageType::Release => OpCode::Request,
            MessageType::Offer | MessageType::Ack | MessageType::Nak => OpCode::Reply,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unexpected,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Invalid = 255,
}

impl DhcpMessageType {
    pub fn from(value: u8) -> DhcpMessageType {
        match value {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            4 => DhcpMessageType::Decline,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            _ => DhcpMessageType::Invalid,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOption {
    UnknownOrPadding(u8) = 0,
    DhcpMessageType(DhcpMessageType) = 53,
    ClientIdentifier(u8, [u8; 6]) = 61,
    SubnetMask([u8; 4]) = 1,
    RenewalTime(u32) = 58,
    RebindingTime(u32) = 59,
    IpAddressLeaseTime(u32) = 51,
    DhcpServerIdentifier([u8; 4]) = 54,
    Router([u8; 4]) = 3,
    DomainNameServer([u8; 4]) = 6,
    CaptivePortal(usize, [u8; 128]) = 160,
    End = 255,
}

impl DhcpOption {
    pub fn from(slice: &[u8]) -> (DhcpOption, usize) {
        let res = match slice[0] {
            53 => DhcpOption::DhcpMessageType(DhcpMessageType::from(slice[2])),
            61 => DhcpOption::ClientIdentifier(slice[2], slice[3..][..6].try_into().unwrap()),
            1 => DhcpOption::SubnetMask(slice[2..][..4].try_into().unwrap()),
            58 => DhcpOption::RenewalTime(u32::from_be_bytes(slice[2..][..4].try_into().unwrap())),
            59 => {
                DhcpOption::RebindingTime(u32::from_be_bytes(slice[2..][..4].try_into().unwrap()))
            }
            51 => DhcpOption::IpAddressLeaseTime(u32::from_be_bytes(
                slice[2..][..4].try_into().unwrap(),
            )),
            54 => DhcpOption::DhcpServerIdentifier(slice[2..][..4].try_into().unwrap()),
            3 => DhcpOption::Router(slice[2..][..4].try_into().unwrap()),
            6 => DhcpOption::DomainNameServer(slice[2..][..4].try_into().unwrap()),
            160 => DhcpOption::CaptivePortal(
                slice[1] as usize,
                slice[2..][..(slice[1] as usize)].try_into().unwrap(),
            ),
            255 => DhcpOption::End,
            _ => DhcpOption::UnknownOrPadding(slice[1]),
        };

        if res != DhcpOption::End {
            (res, 2 + slice[1] as usize)
        } else {
            (DhcpOption::End, 0)
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            DhcpOption::UnknownOrPadding(_) => 0,
            DhcpOption::DhcpMessageType(_) => 53,
            DhcpOption::ClientIdentifier(_, _) => 61,
            DhcpOption::End => 255,
            DhcpOption::SubnetMask(_) => 1,
            DhcpOption::RenewalTime(_) => 58,
            DhcpOption::RebindingTime(_) => 59,
            DhcpOption::IpAddressLeaseTime(_) => 51,
            DhcpOption::DhcpServerIdentifier(_) => 54,
            DhcpOption::Router(_) => 3,
            DhcpOption::DomainNameServer(_) => 6,
            DhcpOption::CaptivePortal(_, _) => 160,
        }
    }
}

pub struct PacketEncoder {
    data: [u8; 1024],
    options_index: usize,
}

impl PacketEncoder {
    pub fn new() -> Self {
        let mut this = Self {
            data: [0u8; 1024],
            options_index: 240,
        };
        this.htype(1);
        this.hlen(6);
        this.hops(0);
        this.magic(DHCP_MAGIC_NUMBER);

        this
    }

    pub fn op(&mut self, op: OpCode) {
        self.data[0] = op as u8;
    }

    pub fn htype(&mut self, htype: u8) {
        self.data[1] = htype;
    }

    pub fn hlen(&mut self, hlen: u8) {
        self.data[2] = hlen;
    }

    pub fn hops(&mut self, hops: u8) {
        self.data[3] = hops;
    }

    pub fn xid(&mut self, xid: u32) {
        self.data[4..][..4].copy_from_slice(&xid.to_be_bytes());
    }

    pub fn secs(&mut self, secs: u16) {
        self.data[8..][..2].copy_from_slice(&secs.to_be_bytes());
    }

    pub fn set_broadcast(&mut self, broadcast: bool) {
        if broadcast {
            self.data[10] = 0b1000_0000;
        } else {
            self.data[10] = 0x0;
        }
    }

    pub fn ciaddr(&mut self, addr: &[u8]) {
        self.data[12..][..4].copy_from_slice(addr);
    }

    pub fn yiaddr(&mut self, addr: &[u8]) {
        self.data[16..][..4].copy_from_slice(addr);
    }

    pub fn siaddr(&mut self, addr: &[u8]) {
        self.data[20..][..4].copy_from_slice(addr);
    }

    pub fn giaddr(&mut self, addr: &[u8]) {
        self.data[24..][..4].copy_from_slice(addr);
    }

    pub fn chaddr(&mut self, addr: &[u8]) {
        self.data[28..][..addr.len()].copy_from_slice(addr);
    }

    pub fn magic(&mut self, magic: u32) {
        self.data[236..][..4].copy_from_slice(&magic.to_be_bytes());
    }

    pub fn encode_option(&mut self, option: DhcpOption) {
        self.data[self.options_index] = option.value();

        let skip = match option {
            DhcpOption::UnknownOrPadding(_l) => panic!("Can't encode unknown option"),
            DhcpOption::DhcpMessageType(t) => {
                self.data[self.options_index + 1] = 1;
                self.data[self.options_index + 2] = t as u8;
                3
            }
            DhcpOption::ClientIdentifier(t, i) => {
                self.data[self.options_index + 1] = 7;
                self.data[self.options_index + 2] = t;
                self.data[self.options_index + 3..][..6].copy_from_slice(&i);
                8
            }
            DhcpOption::End => 1,
            DhcpOption::SubnetMask(mask) => {
                self.data[self.options_index + 1] = 4;
                self.data[self.options_index + 2..][..4].copy_from_slice(&mask);
                6
            }
            DhcpOption::RenewalTime(time) => {
                self.data[self.options_index + 1] = 4;
                self.data[self.options_index + 2..][..4].copy_from_slice(&time.to_be_bytes());
                6
            }
            DhcpOption::RebindingTime(time) => {
                self.data[self.options_index + 1] = 4;
                self.data[self.options_index + 2..][..4].copy_from_slice(&time.to_be_bytes());
                6
            }
            DhcpOption::IpAddressLeaseTime(time) => {
                self.data[self.options_index + 1] = 4;
                self.data[self.options_index + 2..][..4].copy_from_slice(&time.to_be_bytes());
                6
            }
            DhcpOption::DhcpServerIdentifier(ip) => {
                self.data[self.options_index + 1] = 4;
                self.data[self.options_index + 2..][..4].copy_from_slice(&ip);
                6
            }
            DhcpOption::Router(ip) => {
                self.data[self.options_index + 1] = 4;
                self.data[self.options_index + 2..][..4].copy_from_slice(&ip);
                6
            }
            DhcpOption::DomainNameServer(ip) => {
                self.data[self.options_index + 1] = 4;
                self.data[self.options_index + 2..][..4].copy_from_slice(&ip);
                6
            }
            DhcpOption::CaptivePortal(len, bytes) => {
                self.data[self.options_index + 1] = len as u8;
                self.data[self.options_index + 2..][..len].copy_from_slice(&bytes[..len]);
                2 + len
            }
        };

        self.options_index += skip;
    }

    pub fn as_slice(&self, padding: usize) -> &[u8] {
        &self.data[..self.options_index + padding]
    }
}

pub struct PacketDecoder<'a> {
    data: &'a [u8],
    options_index: usize,
}

impl<'a> PacketDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            options_index: 240,
        }
    }

    pub fn op(&self) -> Result<OpCode, Error> {
        match self.data[0] {
            1 => Ok(OpCode::Request),
            2 => Ok(OpCode::Reply),
            _ => Err(Error::Invalid),
        }
    }

    pub fn htype(&self) -> Result<u8, Error> {
        if self.data[1] == 1 {
            Ok(1)
        } else {
            Err(Error::Unexpected)
        }
    }

    pub fn hlen(&self) -> Result<u8, Error> {
        if self.data[2] == 6 {
            Ok(6)
        } else {
            Err(Error::Unexpected)
        }
    }

    pub fn hops(&self) -> Result<u8, Error> {
        Ok(self.data[3])
    }

    pub fn xid(&self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.data[4..][..4].try_into().unwrap()))
    }

    pub fn secs(&self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.data[8..][..2].try_into().unwrap()))
    }

    pub fn is_broadcast(&self) -> Result<bool, Error> {
        Ok(self.data[10] & 0b1000_0000 != 0)
    }

    pub fn ciaddr(&self) -> Result<&'a [u8], Error> {
        Ok(&self.data[12..][..4])
    }

    pub fn yiaddr(&self) -> Result<&'a [u8], Error> {
        Ok(&self.data[16..][..4])
    }

    pub fn siaddr(&self) -> Result<&'a [u8], Error> {
        Ok(&self.data[20..][..4])
    }

    pub fn giaddr(&self) -> Result<&'a [u8], Error> {
        Ok(&self.data[24..][..4])
    }

    pub fn chaddr(&self) -> Result<&'a [u8], Error> {
        Ok(&self.data[28..][..6])
    }

    pub fn sname(&self) -> Result<&'a [u8], Error> {
        Ok(&self.data[34..][..64])
    }

    pub fn file(&self) -> Result<&'a [u8], Error> {
        Ok(&self.data[98..][..128])
    }

    pub fn magic(&self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.data[236..][..4].try_into().unwrap(),
        ))
    }

    // parse options from 240
    pub fn next_option(&mut self) -> Result<DhcpOption, Error> {
        let (option, skip) = DhcpOption::from(&self.data[self.options_index..]);
        self.options_index += skip;
        Ok(option)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_parse_discover() {
        let data = [
            0x01u8, 0x01, 0x06, 0x00, 0xc5, 0x55, 0x10, 0x64, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xd2, 0x45, 0x5a, 0x21, 0xf1, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
            0x53, 0x63, 0x35, 0x01, 0x01, 0x3d, 0x07, 0x01, 0xd2, 0x45, 0x5a, 0x21, 0xf1, 0x26,
            0x39, 0x02, 0x05, 0xdc, 0x3c, 0x0f, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2d,
            0x64, 0x68, 0x63, 0x70, 0x2d, 0x31, 0x30, 0x37, 0x0a, 0x01, 0x03, 0x06, 0x0f, 0x1a,
            0x1c, 0x33, 0x3a, 0x3b, 0x2b, 0xff,
        ];

        let mut decoder = PacketDecoder::new(&data);

        assert_eq!(Ok(OpCode::Request), decoder.op());
        assert_eq!(Ok(1), decoder.htype());
        assert_eq!(Ok(6), decoder.hlen());
        assert_eq!(Ok(0), decoder.hops());
        assert_eq!(Ok(0xc5551064), decoder.xid());
        assert_eq!(Ok(0x0005), decoder.secs());
        assert_eq!(Ok(false), decoder.is_broadcast());
        assert_eq!(Ok(&[0, 0, 0, 0][..]), decoder.ciaddr());
        assert_eq!(Ok(&[0, 0, 0, 0][..]), decoder.yiaddr());
        assert_eq!(Ok(&[0, 0, 0, 0][..]), decoder.siaddr());
        assert_eq!(Ok(&[0, 0, 0, 0][..]), decoder.giaddr());
        assert_eq!(Ok(&[0; 64][..]), decoder.sname());
        assert_eq!(Ok(&[0; 128][..]), decoder.file());
        assert_eq!(Ok(DHCP_MAGIC_NUMBER), decoder.magic());

        assert_eq!(
            Ok(DhcpOption::DhcpMessageType(DhcpMessageType::Discover)),
            decoder.next_option()
        );
        assert_eq!(
            Ok(DhcpOption::ClientIdentifier(1, [210, 69, 90, 33, 241, 38])),
            decoder.next_option()
        );
        assert_eq!(Ok(DhcpOption::UnknownOrPadding(2)), decoder.next_option());
        assert_eq!(Ok(DhcpOption::UnknownOrPadding(15)), decoder.next_option());
        assert_eq!(Ok(DhcpOption::UnknownOrPadding(10)), decoder.next_option());
        assert_eq!(Ok(DhcpOption::End), decoder.next_option());
    }

    #[test]
    fn test_encode_offer() {
        let wanted = [
            0x02, 0x01, 0x06, 0x00, 0xa2, 0x7a, 0xf4, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xac, 0x10, 0x14, 0x68, 0xac, 0x10, 0x14, 0xd3, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x1c, 0xc0, 0xe8, 0x23, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
            0x53, 0x63, 0x35, 0x01, 0x02, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x3a, 0x04, 0x00,
            0x00, 0xa8, 0xc0, 0x3b, 0x04, 0x00, 0x01, 0x27, 0x50, 0x33, 0x04, 0x00, 0x01, 0x51,
            0x80, 0x36, 0x04, 0xac, 0x10, 0x14, 0xd3, 0x03, 0x04, 0xac, 0x10, 0x14, 0x01, 0x06,
            0x04, 0xc0, 0xa8, 0xc9, 0x06, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut encoder = PacketEncoder::new();
        encoder.op(OpCode::Reply);
        encoder.xid(0xa27af44c);
        encoder.set_broadcast(false);
        encoder.yiaddr(&[172, 16, 20, 104]);
        encoder.siaddr(&[172, 16, 20, 211]);
        encoder.chaddr(&[0x00, 0x1c, 0xc0, 0xe8, 0x23, 0x21]);
        encoder.encode_option(DhcpOption::DhcpMessageType(DhcpMessageType::Offer));
        encoder.encode_option(DhcpOption::SubnetMask([255, 255, 255, 0]));
        encoder.encode_option(DhcpOption::RenewalTime(43200));
        encoder.encode_option(DhcpOption::RebindingTime(75600));
        encoder.encode_option(DhcpOption::IpAddressLeaseTime(86400));
        encoder.encode_option(DhcpOption::DhcpServerIdentifier([172, 16, 20, 211]));
        encoder.encode_option(DhcpOption::Router([172, 16, 20, 1]));
        encoder.encode_option(DhcpOption::DomainNameServer([192, 168, 201, 6]));
        encoder.encode_option(DhcpOption::End);

        assert_eq!(wanted, encoder.as_slice(14));
    }
}
