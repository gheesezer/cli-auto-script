# AutoScript
Configuration Automation for Telecommunications Equipment


This software has the functionality of generating a configuration script and exporting to a .txt file, 
after the validation of the settings a serial port number is requested to apply the settings generated 
in an AudioCodes M500 router (Equipment used in the tests), before applying the script performs a firmware 
version check and if it is outdated the application looks for a TFTP server to update the device.
The information needed to generate the script is searched in the local network or folder, but if you do not 
have any valid directory path, you are prompted for the one-to-one entries for the user.