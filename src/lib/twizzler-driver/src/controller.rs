use std::sync::Arc;

use crate::device::{events::DeviceEventStream, Device};

pub struct DeviceController {
    device: Arc<Device>,
    events: DeviceEventStream,
}

impl DeviceController {
    pub fn events(&self) -> &DeviceEventStream {
        &self.events
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    pub fn new_from_device(device: Device) -> Self {
        let device = Arc::new(device);
        Self {
            device: device.clone(),
            events: DeviceEventStream::new(device),
        }
    }
}