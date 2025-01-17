/// External crates for the CLI application
use std::str::FromStr;
use std::net::Ipv4Addr;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use sha2::{Sha256, Digest};


/// Represents the configuration of a network interface.
/// 
/// # Fields
/// - `ip_address`: The IPv4 address of the interface.
/// - `is_up`: A boolean indicating whether the interface is active.
pub struct InterfaceConfig {
    pub ip_address: Ipv4Addr,  
    pub is_up: bool,  
}


lazy_static::lazy_static! {

    /// A thread-safe, globally accessible state that stores network interface configurations.
    /// 
    /// The `NETWORK_STATE` is an `Arc<Mutex<HashMap>>` where:
    /// - The key is the name of the interface (e.g., "ens33").
    /// - The value is a tuple containing:
    ///     - The IPv4 address of the interface.
    ///     - The broadcast address for the interface, calculated based on the subnet prefix length.
    /// 
    /// By default, the `ens33` interface is initialized with the IP `192.168.253.135` 
    /// and a subnet prefix of 24.
    /// 
    pub static ref IFCONFIG_STATE: Arc<Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();

        // Default interface and its configuration
        let default_interface = "ens33".to_string();
        let default_ip = Ipv4Addr::from_str("192.168.253.135").expect("Invalid IP address format");
        let default_broadcast = calculate_broadcast(default_ip, 24);
        
        map.insert(default_interface, (default_ip, default_broadcast));
        
        map
    }));

    
    /// A thread-safe global map that tracks the administrative status of network interfaces.
    ///
    /// # Description
    /// `STATUS_MAP` is a `HashMap` wrapped in an `Arc<Mutex<...>>`, allowing
    /// safe concurrent access and modification. Each key in the map represents
    /// the name of a network interface (e.g., `"ens33"`), and the value is a
    /// `bool` indicating whether the interface is administratively up (`true`)
    /// or administratively down (`false`).
    ///
    /// # Default Behavior
    /// By default, the map is initialized with the `ens33` interface set to
    /// `false` (administratively down). You can modify the default setup
    /// based on your requirements.
    ///
    /// # Thread Safety
    /// The use of `Arc<Mutex<...>>` ensures that multiple threads can safely
    /// access and modify the map, avoiding race conditions.
    pub static ref STATUS_MAP: Arc<Mutex<HashMap<String, bool>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();
    
        // Default interface status (administratively down)
        map.insert("ens33".to_string(), false); // Modify as per your setup
    
        map
    }));

    /// A global, thread-safe state that holds the configuration of network interfaces 
    /// updated via the `ip address` command.
    ///
    /// The `IP_ADDRESS_STATE` is a `Mutex`-protected `HashMap` where:
    /// - The key (`String`) represents the name of the network interface (e.g., `g0/0`).
    /// - The value is a tuple containing:
    ///   - The IP address assigned to the interface (`Ipv4Addr`).
    ///   - The broadcast address derived from the IP and subnet mask (`Ipv4Addr`).
    ///
    /// This state ensures safe concurrent access to the configuration of interfaces 
    /// updated using the `ip address` command. Other commands like `show interfaces`
    /// rely on this data to display the status of the configured interfaces.
    ///
    /// This structure ensures separation from other interface management commands 
    /// like `ifconfig`, which uses its own state (`IFCONFIG_STATE`).
    pub static ref IP_ADDRESS_STATE: Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>> = Mutex::new(HashMap::new());


    /// A global, thread-safe container for storing static routing information.
    ///
    /// This `Mutex<HashMap<String, (Ipv4Addr, String)>>` is used to hold the static routes in a routing table, 
    /// where the key is the destination IP address (as a string) and the value is a tuple containing:
    /// - the network mask (`Ipv4Addr`), 
    /// - the next-hop IP address or the exit interface (stored as a `String`).
    /// 
    /// It is wrapped in a `Mutex` to ensure safe, mutable access from multiple threads.
    pub static ref ROUTE_TABLE: Mutex<HashMap<String, (Ipv4Addr, String)>> = Mutex::new(HashMap::new());


    /// A global configuration for the OSPF (Open Shortest Path First) protocol, 
    /// wrapped in a `Mutex` to allow safe concurrent access.
    ///
    /// The `OSPF_CONFIG` object holds the state and settings for the OSPF protocol 
    /// and ensures thread-safe mutation and access by leveraging Rust's synchronization primitives.
    ///
    /// # Notes
    /// - The `Mutex` ensures that only one thread can modify the configuration at a time.
    /// - Always handle the possibility of a poisoned mutex when locking.
    ///
    pub static ref OSPF_CONFIG: Mutex<OSPFConfig> = Mutex::new(OSPFConfig::new());


    /// A global store for access control lists (ACLs), wrapped in a `Mutex` to ensure thread-safe access.
    ///
    /// This `ACL_STORE` holds a collection of ACLs, indexed by a unique string identifier (either by name or number). 
    /// The store is protected by a `Mutex` to allow safe concurrent access from multiple threads.
    ///
    /// # Notes
    /// - The `Mutex` ensures that only one thread can modify the ACL store at a time, avoiding race conditions.
    /// - You should always handle the possibility of a poisoned mutex when locking, for example by using `.unwrap()` or handling the error gracefully.
    ///
    pub static ref ACL_STORE: Mutex<HashMap<String, AccessControlList>> = Mutex::new(HashMap::new());


    /// A static, thread-safe reference to a `PasswordStore` instance, protected by a `Mutex`.
    /// 
    /// This allows for concurrent access to the `PasswordStore` while ensuring that only one
    /// thread can access the data at a time. The `PasswordStore` is initialized with default
    /// values.
    ///
    /// # Example
    /// ```rust
    /// // Accessing the PASSWORD_STORAGE and modifying the PasswordStore
    /// let mut store = PASSWORD_STORAGE.lock().unwrap();
    /// store.add_password("user1", "password123");
    /// ```
    pub static ref PASSWORD_STORAGE: Mutex<PasswordStore> = Mutex::new(PasswordStore::default());

}


/// Calculates the broadcast address for a given IPv4 address and subnet prefix length.
/// 
/// # Parameters
/// - `ip`: The IPv4 address of the interface.
/// - `prefix_len`: The subnet prefix length (e.g., 24 for a 255.255.255.0 mask).
/// 
/// # Returns
/// - The broadcast address as an `Ipv4Addr`.
/// 
/// # Example
/// ```
/// use std::net::Ipv4Addr;
/// let ip = Ipv4Addr::new(192, 168, 1, 1);
/// let prefix_len = 24;
/// let broadcast = calculate_broadcast(ip, prefix_len);
/// assert_eq!(broadcast, Ipv4Addr::new(192, 168, 1, 255));
/// ```
pub fn calculate_broadcast(ip: Ipv4Addr, prefix_len: u32) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);             // Convert the IP address to a 32-bit integer
    let mask = !0 << (32 - prefix_len);     // Create the subnet mask
    let broadcast_u32 = ip_u32 | !mask;     // Calculate the broadcast address
    Ipv4Addr::from(broadcast_u32)           // Convert back to an Ipv4Addr
}


/// Encrypts a password using the SHA-256 hashing algorithm.
///
/// This function takes a plaintext password, hashes it using SHA-256, and returns the
/// resulting hash as a hexadecimal string.
///
/// # Parameters
/// - `password`: A reference to a string slice (`&str`) representing the password to be hashed.
///
/// # Returns
/// A string containing the hexadecimal representation of the SHA-256 hash of the password.
///
pub fn encrypt_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    format!("{:x}", result)  
}



/// Represents the configuration for the OSPF (Open Shortest Path First) protocol.
///
/// This structure contains the various configurable parameters required for 
/// setting up an OSPF routing process, including interfaces, areas, and neighbors.
///
/// # Fields
/// - `passive_interfaces`: A list of interface names that are configured as passive, meaning 
///   OSPF will not send or receive routing packets on these interfaces.
/// - `distance`: An optional administrative distance value for the OSPF routes.
/// - `default_information_originate`: A boolean flag indicating whether to advertise a default route
///   to other OSPF routers.
/// - `router_id`: An optional unique identifier for the router within the OSPF process.
/// - `areas`: A mapping of area IDs to their respective [`AreaConfig`] configurations.
/// - `networks`: A mapping of network prefixes to their associated subnet masks.
/// - `neighbors`: A mapping of OSPF neighbor IPv4 addresses to their optional priority values.
/// - `process_id`: An optional identifier for the OSPF routing process.
///
#[derive(Debug, Clone)]
pub struct OSPFConfig {
    pub passive_interfaces: Vec<String>,
    pub distance: Option<u32>,
    pub default_information_originate: bool,
    pub router_id: Option<String>,
    pub areas: HashMap<String, AreaConfig>,
    pub networks: HashMap<String, u32>,
    pub neighbors: HashMap<Ipv4Addr, Option<u32>>,
    pub process_id: Option<u32>,
}


/// Represents the configuration for a specific OSPF area.
///
/// Each OSPF area can have unique settings for authentication, cost, and whether it is 
/// a stub area.
///
/// # Fields
/// - `authentication`: Indicates whether authentication is enabled for this area.
/// - `stub`: Indicates whether this area is configured as a stub area.
/// - `default_cost`: An optional cost value for routes advertised into this stub area.
///
#[derive(Debug, Clone)]
pub struct AreaConfig {
    pub authentication: bool,
    pub stub: bool,
    pub default_cost: Option<u32>,
}

impl OSPFConfig {
    /// Configuration for OSPF (Open Shortest Path First) routing protocol.
    ///
    /// The `OSPFConfig` struct encapsulates the configuration details for managing OSPF settings in a CLI-based
    /// environment. This includes defining areas, networks, neighbors, and other protocol-specific parameters.
    ///
    /// # Fields
    /// - `passive_interfaces`: A vector of interfaces that are marked as passive (do not send OSPF packets).
    /// - `distance`: An optional administrative distance for OSPF routes.
    /// - `default_information_originate`: A boolean indicating whether default information is originated.
    /// - `router_id`: An optional router ID used in the OSPF process.
    /// - `areas`: A `HashMap` mapping OSPF area IDs to their respective configurations.
    /// - `networks`: A `HashMap` mapping networks to their associated area IDs.
    /// - `neighbors`: A `HashMap` of neighbors configured for OSPF communication.
    /// - `process_id`: An optional process ID for the OSPF instance.
    pub fn new() -> Self {
        Self {
            passive_interfaces: Vec::new(),
            distance: None,
            default_information_originate: false,
            router_id: None,
            areas: HashMap::new(),
            networks: HashMap::new(),
            neighbors: HashMap::new(),
            process_id: None,
        }
    }
}


/// Represents a single entry in an Access Control List (ACL).
///
/// This structure defines the conditions for matching network traffic in an ACL, 
/// including the action to take (allow or deny), source and destination addresses, 
/// protocols, ports, and operators for comparison.
///
/// # Fields
/// - `action`: The action to take when a packet matches this ACL entry (e.g., "allow" or "deny").
/// - `source`: The source IP address or network to match.
/// - `destination`: The destination IP address or network to match.
/// - `protocol`: An optional protocol to match, such as "TCP", "UDP", or "ICMP".
/// - `matches`: An optional number of matches (such as packet count) to track how many packets meet the criteria.
/// - `source_operator`: An optional operator (e.g., "gt", "lt") for comparing source values (used for port matching).
/// - `source_port`: An optional source port to match, typically used with protocols like TCP or UDP.
/// - `destination_operator`: An optional operator (e.g., "gt", "lt") for comparing destination values.
/// - `destination_port`: An optional destination port to match, typically used with TCP or UDP.
///
#[derive(Debug)]
pub struct AclEntry {
    pub action: String,
    pub source: String,
    pub destination: String,
    pub protocol: Option<String>,
    pub matches: Option<u32>, 
    pub source_operator: Option<String>, 
    pub source_port: Option<String>,  
    pub destination_operator: Option<String>, 
    pub destination_port: Option<String>, 
}


/// Represents an Access Control List (ACL), which contains multiple ACL entries.
///
/// This structure holds a list of ACL entries, each of which defines a rule for filtering network traffic.
/// ACLs are often used in networking devices such as routers and firewalls to control access to resources.
///
/// # Fields
/// - `number_or_name`: The unique identifier for the ACL, either as a number or a name.
/// - `entries`: A list of [`AclEntry`] objects, each representing a specific rule in the ACL.
///
#[derive(Debug)]
pub struct AccessControlList {
    pub number_or_name: String,
    pub entries: Vec<AclEntry>,
}


/// Represents the NTP (Network Time Protocol) association details for a device.
/// 
/// This structure holds information related to the NTP association, such as the server's
/// address, reference clock, synchronization status, and time offset values.
#[derive(Default)]
pub struct NtpAssociation {
    pub address: String,
    pub ref_clock: String,
    pub st: u8,
    pub when: String,
    pub poll: u8,
    pub reach: u8,
    pub delay: f64,
    pub offset: f64,
    pub disp: f64,
}


/// A structure for storing passwords used in the CLI.
///
/// The `PasswordStore` struct is designed to hold two optional passwords:
/// - `enable_password`: A plaintext password used for accessing privileged mode.
/// - `enable_secret`: A hashed or encrypted password used as an alternative to `enable_password`.
///
/// # Fields
/// - `enable_password`: An `Option<String>` that stores the plaintext enable password. Defaults to `None`.
/// - `enable_secret`: An `Option<String>` that stores the hashed or encrypted enable secret. Defaults to `None`.
///
/// # Default Implementation
/// The `Default` trait is implemented to initialize `PasswordStore` with both fields set to `None`.
///
/// # Example
/// ```rust
/// let password_store = PasswordStore::default();
/// assert!(password_store.enable_password.is_none());
/// assert!(password_store.enable_secret.is_none());
///
/// let password_store = PasswordStore {
///     enable_password: Some("plaintext_password".to_string()),
///     enable_secret: Some("hashed_secret".to_string()),
/// };
/// println!("Enable Password: {:?}", password_store.enable_password);
/// println!("Enable Secret: {:?}", password_store.enable_secret);
/// ```
///
/// # Usage
/// This struct can be used to store and retrieve passwords securely within a CLI context. 
/// You can initialize it with default values or specify the passwords during creation.
pub struct PasswordStore {
    pub enable_password: Option<String>,
    pub enable_secret: Option<String>,
}

impl Default for PasswordStore {
    /// Creates a new instance of `PasswordStore` with default values.
    ///
    /// Both `enable_password` and `enable_secret` are initialized to `None`
    fn default() -> Self {
        PasswordStore {
            enable_password: None,
            enable_secret: None,
        }
    }
}


/// Sets the enable password in the `PasswordStore`.
/// 
/// This function updates the stored `enable_password` to the provided value.
///
/// # Parameters
/// - `password`: A reference to the password string to set as the enable password.
pub fn set_enable_password(password: &str) {
    let mut storage = PASSWORD_STORAGE.lock().unwrap();
    storage.enable_password = Some(password.to_string());
}


/// Sets the enable secret in the `PasswordStore`.
/// 
/// This function updates the stored `enable_secret` to the provided value.
///
/// # Parameters
/// - `secret`: A reference to the secret string to set as the enable secret.
pub fn set_enable_secret(secret: &str) {
    let mut storage = PASSWORD_STORAGE.lock().unwrap();
    storage.enable_secret = Some(secret.to_string());
}


/// Retrieves the stored enable password from the `PasswordStore`.
/// 
/// # Returns
/// An `Option<String>`, containing the enable password if set, or `None` if not set.
pub fn get_enable_password() -> Option<String> {
    let storage = PASSWORD_STORAGE.lock().unwrap();
    storage.enable_password.clone()
}



/// Retrieves the stored enable secret from the `PasswordStore`.
/// 
/// # Returns
/// An `Option<String>`, containing the enable secret if set, or `None` if not set.
pub fn get_enable_secret() -> Option<String> {
    let storage = PASSWORD_STORAGE.lock().unwrap();
    storage.enable_secret.clone()
}