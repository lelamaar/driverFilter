# driverFilter
A filter driver for Windows 7/8/8.1/10 that allows you to restrict the access rights of processes to objects in the file system.
The File system Mini-filter driver template was used as a basis. To start, you need a WDK for your version of Windows.

# Functions
This driver can:
- read information from the configuration file conf.txt;
- block the process of reading, depending on the rights;
- block the process of writing, depending on the rights;
- Simultaneously block the process of reading and writing, depending on the rights.

# Configurating
The configuration file conf.txt should be located in Windows/System32.
It has the following structure:

<path_to_file_1> <path_to_process_1> xy
<path_to_file_n> <path_to_process_n> xy

Two numbers - xy, which can be either 0 (enable) or 1 (disable); the number x is responsible for writing, and y for reading.

# Algorithm
Access is blocked according to the following algorithm:
1) getting the name of the file that the process is accessing;
2) search for a matching file name in the access_array list;
3) if there is a match, the process name is obtained;
4) comparison of the name with the proc field of the structure;
5) if there is a match, we check the number field (this field contains two numbers - xy, which can take values ​​either 0 (permission) or 1 (prohibition); number x is responsible for writing, and y for reading);
6) depending on the value of number, enable / disable is performed.

# Debug and start
The driver can be debugged using the DbgView utility. Driver registration and start can be done through OSR Driver Loader.