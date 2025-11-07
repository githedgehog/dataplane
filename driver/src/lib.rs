// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub trait Driver {
    type Configure: Configure;
    type Start: Start;
    type Stop: Stop;
}

pub trait Configure: Sized {
    type Configuration;
    type Error;
    fn configure(configuration: Self::Configuration) -> Result<Self, <Self as Configure>::Error>;
}

pub trait Start {
    type Started: Stop;
    type Error;
    fn start(self) -> Result<Self::Started, Self::Error>;
}

pub trait Stop {
    type Outcome;
    fn stop(self) -> Self::Outcome;
}
