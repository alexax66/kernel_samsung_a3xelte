#
# Makefile for Secure OS control sysfs
#
obj-$(CONFIG_SECURE_OS_CONTROL) += sec_os_ctrl.o

# MobiCore kernel driver path
GUD_ROOT_FOLDER := drivers/gud/

# Includes MobiCore kernel driver
ccflags-y += -I$(srctree)/$(GUD_ROOT_FOLDER)/MobiCoreDriver
ccflags-y += -I$(srctree)/$(GUD_ROOT_FOLDER)/MobiCoreDriver/public
