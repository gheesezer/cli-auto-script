# AutoScript
Configuration automation for telecommunications equipment

This software has the functionality to generate a configuration script from a template file and export it to a .txt file,
after configuration validation, a serial port number that is requested to apply the generated settings
on an AudioCodes M500 router (equipment used in the tests), before applying the script runs a firmware
version checking and if it is out of date, the application looks for a TFTP server to update the device.
The information needed to generate the script is searched on the local network or folder, but if you don't
has a valid directory path, you are prompted to enter the entries one by one for the user.

In this prototype, an Audiocodes Mediant 500 - MSBR router was used, but it can be modified to configure or update any type of router, switch or telecommunications equipment with CLI access through the serial (Cisco, HP, Extreme, Juniper...).

The test equipment has a baud rate of 115200 on the serial port and is updated to firmware version 'Software Version: 6.80A.286.002'. These data can be modified according to the equipment that will be updated and configured.

The development and testing environment was in Windows and the directories and commands imported into the system need to be changed to another operating system.

I am assuming that to automate the configurations performed on a serial port of telecom equipment you have the necessary knowledge to access CLI through Putty, Teraterm, Hyperterminal or Minicom and can prepare a TFTP server for updating after the necessary adjustments of each equipment model.