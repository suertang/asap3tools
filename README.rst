asap3tools
=======================

The project's goal is to develop python3 interface to an ASAP3 host.

ASAP3 is a socket based protocol to interface a calibration tool.

Some of ASAP3 features are:
- calibration parameters, such as single values, curves or maps can be changed
- online measurements
- remote data recording for later transmission to the client system
- remote control of the calibration tool concerning dataset management,
  e.g. copy, rename, flashing of ECU

ASAP3 uses common ASAP "wording" such as "label","measurement","characteristic" etc. 

Standard socket is localhost at port 22222
