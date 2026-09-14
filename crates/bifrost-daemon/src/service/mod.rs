//! Le daemon en service Windows.
//!
//! [`spec`] decrit ce que le service doit etre, en donnee pure et testee
//! partout, y compris en CI Linux. [`scm`] fait les appels au gestionnaire de
//! controle des services, et n'existe que sous Windows.

pub mod spec;

#[cfg(windows)]
pub mod scm;
