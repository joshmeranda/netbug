use crate::protocols::Protocol;

enum IeeEthernet {
    Ieee802_2(Ethernet2),
    Ieee802_3(Ethernet3),
}

impl From<Ethernet2> for IeeEthernet {
    fn from(ethernet: Ethernet2) -> Self {
        Self::Ieee802_2(ethernet)
    }
}

impl From<Ethernet3> for IeeEthernet {
    fn from(ethernet: Ethernet3) -> Self {
        Self::Ieee802_3(ethernet)
    }
}

impl From<&[u8]> for IeeEthernet {
    fn from(data: &[u8; 22]) -> IeeEthernet {
        let length = u16::from_be_bytes(data[20..22]);

        if length > 1500 {
            todo!()
        } else {
            todo!()
        }
    }
}

/// The ethernet packet for IEE 802.2
struct Ethernet2 {
    destination: [u8; 6],

    source: [u8; 6],

    protocol: Protocol,
}

/// The ethernet packet for IEE 802.3
struct Ethernet3 {
    destination: [u8; 6],

    source: [u8; 6],

    length: u8,

    frame_check_sequence: u8
}