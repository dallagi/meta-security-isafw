**meta-security-isafw** is an OE layer that allows enabling the Image
Security Analysis Framework (isafw) for your image builds. 

The primary purpose of isafw is to provide an extensible 
framework for analysing different security aspects of images 
during the build process.

The isafw project itself can be found at 
    https://github.com/01org/isafw

The framework supports a number of callbacks (such as 
process_package(), process_filesystem(), and etc.) that are invoked 
by the bitbake during different stages of package and image build. 
These callbacks are then forwarded for processing to the avaliable 
ISA FW plugins that have registered for these callbacks. 
Plugins can do their own processing on each stage of the build 
process and produce security reports. 

Dependencies
------------

The **meta-security-isafw** layer depends on the Open Embeeded
core layer:

    git://git.openembedded.org/openembedded-core


Usage
-----

In order to enable the isafw during the image build, please add 
the following line to your build/conf/local.conf file:

INHERIT += "isafw"

Next you need to update your build/conf/bblayers.conf file with the
location of meta-security-isafw layer on your filesystem along with
any other layers needed. e.g.:

BBLAYERS ?= " \
  /OE/oe-core/meta \
  /OE/meta-security-isafw \
  "
 
Also, some isafw plugins require network connection, so in case of a
proxy setup please make sure to export http_proxy variable into your 
environment.

In order to produce image reports, you can execute image build 
normally. For example:

bitbake core-image-minimal

If you are only interested to produce a report based on packages 
and without building an image, please use:

bitbake -c analyse_sources_all core-image-minimal


Logs
----

All isafw plugins by default create their logs under the 
${LOG_DIR}/isafw-report/ directory, where ${LOG_DIR} is a bitbake 
default location for log files. If you wish to change this location, 
please define ISAFW_REPORTDIR variable in your local.conf file. 

Patches
-------

Please submit any patches via Github pull requests.

Maintainer: Elena Reshetova elena.reshetova@intel.com

