use std::collections::linked_list::{self, LinkedList};
use std::mem;
use std::path::PathBuf;

use std::rc::Rc;
use std::result;

use api_server::request::sync::{DriveDescription, DriveError, Error as SyncError,
                                NetworkInterfaceBody, OkStatus as SyncOkStatus};
use net_util::{Tap, TapError};

// TODO: I think this module should be broken up into multiple files, one for each of drives,
// network interfaces, and vsocks (and limiters maybe at some point).

type Result<T> = result::Result<T, DriveError>;

/// Use this structure to set up the Block Device before booting the kernel
#[derive(PartialEq, Debug, Clone)]
pub struct BlockDeviceConfig {
    pub drive_id: String,
    pub path_on_host: PathBuf,
    pub is_root_device: bool,
}

// Wrapper for the collection that holds all the Block Devices Configs
pub struct BlockDeviceConfigs {
    pub config_list: LinkedList<BlockDeviceConfig>,
    has_root_block: bool,
}

impl From<DriveDescription> for BlockDeviceConfig {
    fn from(item: DriveDescription) -> Self {
        BlockDeviceConfig {
            drive_id: item.drive_id,
            path_on_host: PathBuf::from(item.path_on_host),
            is_root_device: item.is_root_device,
        }
    }
}

impl BlockDeviceConfigs {
    pub fn new() -> BlockDeviceConfigs {
        BlockDeviceConfigs {
            config_list: LinkedList::<BlockDeviceConfig>::new(),
            has_root_block: false,
        }
    }

    pub fn has_root_block_device(&self) -> bool {
        return self.has_root_block;
    }

    pub fn contains_drive_path(&self, drive_path: PathBuf) -> bool {
        for drive_config in self.config_list.iter() {
            if drive_config.path_on_host == drive_path {
                return true;
            }
        }
        return false;
    }

    pub fn contains_drive_id(&self, drive_id: String) -> bool {
        for drive_config in self.config_list.iter() {
            if drive_config.drive_id == drive_id {
                return true;
            }
        }
        return false;
    }

    /// This function adds a Block Device Config to the list. The root block device is always
    /// added to the beginning of the list. Only one root block device can be added.
    pub fn add(&mut self, block_device_config: BlockDeviceConfig) -> Result<()> {
        // check if the path exists
        if !block_device_config.path_on_host.exists() {
            return Err(DriveError::InvalidBlockDevicePath);
        }

        if self.contains_drive_path(block_device_config.path_on_host.clone()) {
            return Err(DriveError::BlockDevicePathAlreadyExists);
        }

        // check whether the Device Config belongs to a root device
        // we need to satify the condition by which a VMM can only have on root device
        if block_device_config.is_root_device {
            if self.has_root_block {
                return Err(DriveError::RootBlockDeviceAlreadyAdded);
            } else {
                // Root Device should be the first in the list
                self.config_list.push_front(block_device_config);
                self.has_root_block = true;
            }
        } else {
            self.config_list.push_back(block_device_config);
        }

        Ok(())
    }
}

pub struct NetworkInterfaceConfig {
    // The request body received from the API side.
    _body: NetworkInterfaceBody,
    // We extract the id from the body and hold it as a reference counted String. This should
    // come in handy later on, when we'll need the id to appear in a number of data structures
    // to implement efficient lookup, update, deletion, etc.
    id: Rc<String>,
    // We open the tap that will be associated with the virtual device as soon as the PUT request
    // arrives from the API. We want to see if there are any errors associated with the operation,
    // and if so, we want to report the failure back to the API caller immediately. This is an
    // option, because the inner value will be moved to the actual virtio net device before boot.
    pub tap: Option<Tap>,
}

impl NetworkInterfaceConfig {
    pub fn try_from_body(mut body: NetworkInterfaceBody) -> result::Result<Self, TapError> {
        let id = Rc::new(mem::replace(&mut body.iface_id, String::new()));

        // TODO: rework net_util stuff such that references would suffice here, instead
        // of having to move things around.
        let tap = Tap::open_named(body.host_dev_name.as_str())?;

        Ok(NetworkInterfaceConfig {
            _body: body,
            id,
            tap: Some(tap),
        })
    }

    pub fn id_as_str(&self) -> &str {
        self.id.as_str()
    }

    pub fn take_tap(&mut self) -> Option<Tap> {
        self.tap.take()
    }
}

pub struct NetworkInterfaceConfigs {
    // We use just a list for now, since we only add interfaces as this point.
    if_list: LinkedList<NetworkInterfaceConfig>,
}

impl NetworkInterfaceConfigs {
    pub fn new() -> Self {
        NetworkInterfaceConfigs {
            if_list: LinkedList::new(),
        }
    }

    pub fn put(&mut self, body: NetworkInterfaceBody) -> result::Result<SyncOkStatus, SyncError> {
        let cfg = NetworkInterfaceConfig::try_from_body(body).map_err(SyncError::OpenTap)?;

        for x in self.if_list.iter() {
            if x.id_as_str() == cfg.id_as_str() {
                return Err(SyncError::UpdateNotImplemented);
            }
        }
        self.if_list.push_back(cfg);
        Ok(SyncOkStatus::Created)
    }

    pub fn iter_mut(&mut self) -> linked_list::IterMut<NetworkInterfaceConfig> {
        self.if_list.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    // Helper function for creating a dummy file
    // The filename has to be unique among all tests because the tests are run on many threads
    fn create_dummy_path(filename: String) -> PathBuf {
        let _file = File::create(filename.clone());
        return PathBuf::from(filename);
    }

    // Helper function for deleting a dummy file
    fn delete_dummy_path(filename: String) {
        let _rs = std::fs::remove_file(filename);
    }

    #[test]
    fn test_create_block_devices_configs() {
        let block_devices_configs = BlockDeviceConfigs::new();
        assert_eq!(block_devices_configs.has_root_block_device(), false);
        assert_eq!(block_devices_configs.config_list.len(), 0);
    }

    #[test]
    fn test_add_non_root_block_device() {
        let dummy_filename = String::from("non_root_block_device");
        let dummy_path = create_dummy_path(dummy_filename.clone());

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path,
            is_root_device: false,
            drive_id: String::from("1"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device.clone())
                .is_ok()
        );
        assert_eq!(block_devices_configs.has_root_block, false);
        assert_eq!(block_devices_configs.config_list.len(), 1);
        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &dummy_block_device);

        delete_dummy_path(dummy_filename);
    }

    #[test]
    fn test_add_one_root_block_device() {
        let dummy_filename = String::from("one_root_block_device");
        let dummy_path = create_dummy_path(dummy_filename.clone());

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path,
            is_root_device: true,
            drive_id: String::from("1"),
        };
        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device.clone())
                .is_ok()
        );
        assert_eq!(block_devices_configs.has_root_block, true);
        assert_eq!(block_devices_configs.config_list.len(), 1);
        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &dummy_block_device);

        delete_dummy_path(dummy_filename);
    }

    #[test]
    fn test_add_two_root_block_devices_configs() {
        let dummy_filename_1 = String::from("two_root_block_devices_configs_1");
        let dummy_path_1 = create_dummy_path(dummy_filename_1.clone());
        let root_block_device_1 = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            drive_id: String::from("1"),
        };

        let dummy_filename_2 = String::from("two_root_block_devices_configs_2");
        let dummy_path_2 = create_dummy_path(dummy_filename_2.clone());
        let root_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2.clone(),
            is_root_device: true,
            drive_id: String::from("2"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(block_devices_configs.add(root_block_device_1).is_ok());
        let actual_error = format!(
            "{:?}",
            block_devices_configs.add(root_block_device_2).unwrap_err()
        );
        let expected_error = format!("{:?}", DriveError::RootBlockDeviceAlreadyAdded);
        assert_eq!(expected_error, actual_error);

        delete_dummy_path(dummy_filename_1);
        delete_dummy_path(dummy_filename_2);
    }

    #[test]
    /// Test BlockDevicesConfigs::add when you first add the root device and then the other devices
    fn test_add_root_block_device_first() {
        let dummy_filename_1 = String::from("root_block_device_first_1");
        let dummy_path_1 = create_dummy_path(dummy_filename_1.clone());
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            drive_id: String::from("1"),
        };

        let dummy_filename_2 = String::from("root_block_device_first_2");
        let dummy_path_2 = create_dummy_path(dummy_filename_2.clone());
        let dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2.clone(),
            is_root_device: false,
            drive_id: String::from("2"),
        };

        let dummy_filename_3 = String::from("root_block_device_first_3");
        let dummy_path_3 = create_dummy_path(dummy_filename_3.clone());
        let dummy_block_device_3 = BlockDeviceConfig {
            path_on_host: dummy_path_3.clone(),
            is_root_device: false,
            drive_id: String::from("3"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(block_devices_configs.add(root_block_device.clone()).is_ok());
        assert!(
            block_devices_configs
                .add(dummy_block_device_2.clone())
                .is_ok()
        );
        assert!(
            block_devices_configs
                .add(dummy_block_device_3.clone())
                .is_ok()
        );

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.config_list.len(), 3);

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_3);

        delete_dummy_path(dummy_filename_1);
        delete_dummy_path(dummy_filename_2);
        delete_dummy_path(dummy_filename_3);
    }

    #[test]
    /// Test BlockDevicesConfigs::add when you add other devices first and then the root device
    fn test_root_block_device_add_last() {
        let dummy_filename_1 = String::from("root_block_device_first_1");
        let dummy_path_1 = create_dummy_path(dummy_filename_1.clone());
        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path_1.clone(),
            is_root_device: true,
            drive_id: String::from("1"),
        };

        let dummy_filename_2 = String::from("root_block_device_first_2");
        let dummy_path_2 = create_dummy_path(dummy_filename_2.clone());
        let dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path_2.clone(),
            is_root_device: false,
            drive_id: String::from("2"),
        };

        let dummy_filename_3 = String::from("root_block_device_first_3");
        let dummy_path_3 = create_dummy_path(dummy_filename_3.clone());
        let dummy_block_device_3 = BlockDeviceConfig {
            path_on_host: dummy_path_3.clone(),
            is_root_device: false,
            drive_id: String::from("3"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device_2.clone())
                .is_ok()
        );
        assert!(
            block_devices_configs
                .add(dummy_block_device_3.clone())
                .is_ok()
        );
        assert!(block_devices_configs.add(root_block_device.clone()).is_ok());

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.config_list.len(), 3);

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        // The root device should be first in the list no matter of the order in which the devices were added
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_3);

        delete_dummy_path(dummy_filename_1);
        delete_dummy_path(dummy_filename_2);
        delete_dummy_path(dummy_filename_3);
    }
}