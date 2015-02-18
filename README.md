
Author: Udit K Gupta
SBU ID: 109275987

                                                            INTRODUCTION

1. This project aims to design, implement and test a role based file access control module in the kernel.
2. The Project implements a basic RBAC model as a kernel level refercne monitor that would satisfy regular user demand for file system acces control.
3. The monitor uses the Linux Security Module (LSM) APIs/hooks and mediate only few basic inode access (inode_create,inode_mkdir,inode_rmdir,inode_unlink,inode_rename) in the current version.


                                                            TECHNICAL DETAILS
1. The security module has been named rbslinux (Role Based Security Linux) and has been added in the kernel 3.14.17 (vanilla) as s default security module. All other security options(like selinux) has been disabled in the kernel configuration.

2. The security module uses the security_operations structure and register rbslinux_* functions for inode access hooks. The current version implement only five of them.

3. All rbslinux_* functions read the configuration file (/etc/rbslinux.conf) for all the users (user ids greater than 1000) and their roles. Role can be Admin (0) or Non-admin (1). Depending on the role, inode access are permitted.

                                                            INSTALLATION STEPS
1. Copy the rbslinux directory to the linux kernel security folder (parallel to selinux folder directroy).
2. Change the KConfig file in the security folder of the kernel as per the chnages in the KConfig file of archive. (This is different from the one inside rbslinux directory)
3. Change the Makefile in the security folder of the kernel as per the chnages in the Makefile of archive. (This is different from the one inside rbslinux directory)
4. To remove the other security options and make rbslinux as the default security module, incorporate configurations from the .config file (in the archive) into your kernel.


                                                                
http://blog.ptsecurity.com/2012/09/writing-linux-security-module.html


NOTE: 
1. Archive mentioned in this documentation refers to the CSE509 archive included as part of the project submission. 
2. For user-space utility for RBAC control, see README inside user-space utility folder.
3. See README inside test folder for testing related queries.
