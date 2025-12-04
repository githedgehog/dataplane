// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub trait Configure {
    type Configuration;
    type Configured: Start;
    type Error;
    fn configure(configuration: Self::Configuration) -> Result<Self::Configured, Self::Error>;
}

pub trait Start {
    type Started: Stop;
    type Error;
    fn start(self) -> Result<Self::Started, Self::Error>;
}

pub trait Stop {
    type Outcome;
    type Error;
    fn stop(self) -> Result<Self::Outcome, Self::Error>;
}
