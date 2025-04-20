'''
Created on Mar 3, 2013

@author: Muhammed Abdallah Muhammed

Copyright (c) 2024 Muhammed Abdallah Muhammed

'''

import re
import MySQLdb

import logging

# The below Python code sets up a logger named 'myapp' that writes log messages to a file named
# "FWConfProcessMain.log" located at "/root/Firewalls/config_BU/". It configures the logger to include
# the timestamp, log level, and message in the log entries. The logger is set to log messages with a
# level of DEBUG or higher. Finally, it logs an informational message "Conf Files processing starts"
# to indicate the start of configuration files processing.
logger = logging.getLogger('myapp')
hdlr = logging.FileHandler("/root/Firewalls/config_BU/FWConfProcessMain.log")
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.DEBUG)

logger.info('Conf Files processing starts')

a = 'a..!b...c???d;;'
chars = [',', '!', ';', '?']

print re.sub('[%s]' % ''.join(chars), '', a)

# The below code is establishing a connection to a MySQL database using the MySQLdb library in Python.
# It is connecting to a database named "FWConfig" on the localhost server

db = MySQLdb.connect(host="localhost", user="#####", passwd="######", db="FWConfig")

cur = db.cursor()

charstobreplaced = [',', '!',  ';', '?' , '\'' , '"','\\']

file_fws = open("/root/Firewalls/config_BU/files.txt")

# The above code is a Python script that is executing a series of SQL DELETE statements on multiple
# tables in a database. It is deleting all records from the tables `addressobjects`, `group_members`,
# `groups`, `mip`, `policies`, `policies_details`, `scheduler`, and `services` in the `fwconfig`
# schema. After executing the DELETE statements, the code closes the cursor and creates a new cursor
# for further database operations.
sql = "DELETE FROM fwconfig.addressobjects ; DELETE FROM fwconfig.group_members ; DELETE FROM fwconfig.groups ; DELETE FROM fwconfig.mip ; DELETE FROM fwconfig.policies ; DELETE FROM fwconfig.policies_details ; DELETE FROM fwconfig.scheduler ; DELETE FROM fwconfig.services ;"

cur.execute(sql);

cur.close()

cur = db.cursor()

while 1:
    line_fwfile = file_fws.readline()
    if not line_fwfile:
        break

    counter  = 0
    counter_mip = 0
    counter_service = 0
    counter_schedular = 0
    counter_disable = 0
    counter_Group = 0
    counter_grp_member = 0
    counter_Group_srv = 0
    counter_grp_member_srv = 0
    
    tempstr = "/root/Firewalls/config_BU/" + line_fwfile.strip()
    file_currentFW = open(tempstr)
    logger.debug("Firewall conf file >>>>>>>>>   " + line_fwfile.strip())
    
    
    # The above code snippet is a Python script that reads lines from a file (`file_currentFW`) and uses
    # regular expressions to match and extract specific patterns from each line.
    while 1:
        line = file_currentFW.readline()
        if not line:
            break
        
        # The above code is using regular expressions in Python to match and extract specific patterns from
        # input lines. Each `re.match` function call is attempting to match a specific pattern in the `line`
        # variable using the provided regular expression pattern.
        matchObj_address1 = re.match( r'set\saddress\s"([^"]*)"\s"([^"]*)"\s([0-9]+(?:\.[0-9]+){3})\s([0-9]+(?:\.[0-9]+){3})(\s"[^"]*")?', line, re.M|re.I)
        matchObj_address2 = re.match( r'set\saddress\s"([^"]*)"\s"([^"]*)"\s([^\d][^"]*)(\s\s"([^"]*)")?\n', line, re.M|re.I)
        matchObj_mip = re.match(r'set\sinterface\s"([^"]*)"\smip\s([0-9]+(?:\.[0-9]+){3})\shost\s([0-9]+(?:\.[0-9]+){3})\snetmask\s([0-9]+(?:\.[0-9]+){3})\svr\s"([^"]*)"', line, re.M|re.I)
        matchObj_service = re.match(r'set\sservice\s"([^"]*)"\s(?:protocol|\+)\s(\w*)\ssrc-port\s([^\s]*)\sdst-port\s([^\s]*)' , line , re.M|re.I)
        matchObj_Scheduler = re.match(r'set\sscheduler\s"([^"]*)"\s((?:once|recurrent))\sstart\s([^\s]*\s[^\s]*)\sstop\s([^\s]*\s[^\s]*)(\scomment\s"([^"]*)")?', line ,re.M|re.I )
        matchObj_Group = re.match(r'set\sgroup\saddress\s"([^"]*)"\s"([^"]*)"(\scomment\s"([^"]*)")?\n' , line , re.M|re.I )
        matchObj_Group_member = re.match(r'set\sgroup\saddress\s"([^"]*)"\s"([^"]*)"\sadd\s"([^"]*)"' , line , re.M|re.I )
        matchObj_Group_service = re.match(r'set\sgroup\sservice\s"([^"]*)"(?:\r|(\s(comment)\s"([^"]*)")?)\n' , line , re.M|re.I )
        matchObj_Group_service_member = re.match(r'set\sgroup\sservice\s"([^"]*)"\sadd\s"([^"]*)"' , line , re.M|re.I )
        
        if matchObj_address1:
            if (matchObj_address1.group(5)):
                sql = "INSERT INTO `fwconfig`.`AddressObjects` (`Zone`,`ObjectName`,`FullName`,`IP`,`SubnetMask`,`type`,`comment`, `Firewall`) VALUES ('" + matchObj_address1.group(1).strip() + "','" + matchObj_address1.group(2).strip() + "', '-' ,'" + matchObj_address1.group(3).strip()+ "','" + matchObj_address1.group(4).strip()+ "',0,'" + matchObj_address1.group(5).strip().translate(None, ''.join(charstobreplaced)) + "', '"+line_fwfile.strip()+"');"
            else :
                sql = "INSERT INTO `fwconfig`.`AddressObjects` (`Zone`,`ObjectName`,`FullName`,`IP`,`SubnetMask`,`type`,`comment`, `Firewall`) VALUES ('" + matchObj_address1.group(1).strip() + "','" + matchObj_address1.group(2).strip() + "', '-' ,'" + matchObj_address1.group(3).strip()+ "','" + matchObj_address1.group(4).strip()+ "',0,'', '"+line_fwfile.strip()+"');"       
            cur.execute(sql)
            counter = counter + 1
        
        elif matchObj_address2:
            if (matchObj_address2.group(4)):
                sql = "INSERT INTO `fwconfig`.`AddressObjects` (`Zone`,`ObjectName`,`FullName`,`IP`,`SubnetMask`,`type`,`comment`, `Firewall`) VALUES ('" + matchObj_address2.group(1).strip() + "','" + matchObj_address2.group(2).strip() + "','" + matchObj_address2.group(3).strip()+ "','-','-',1,'" + matchObj_address2.group(5).strip().translate(None, ''.join(charstobreplaced))+ "', '"+line_fwfile.strip()+"');"
            else :
                sql = "INSERT INTO `fwconfig`.`AddressObjects` (`Zone`,`ObjectName`,`FullName`,`IP`,`SubnetMask`,`type`,`comment`, `Firewall`) VALUES ('" + matchObj_address2.group(1).strip() + "','" + matchObj_address2.group(2).strip() + "','" + matchObj_address2.group(3).strip()+ "','-','-',1,'', '"+line_fwfile.strip()+"');"  
            counter = counter + 1
            cur.execute(sql)
        
        elif matchObj_mip:
            sql = "INSERT INTO fwconfig.mip (Interface, MappedIP, HostIP, NetMask, VR, Firewall, Revision) VALUES ('" + matchObj_mip.group(1) + "', '" + matchObj_mip.group(2) + "', '" + matchObj_mip.group(3) + "', '" + matchObj_mip.group(4) + "', '" + matchObj_mip.group(5) + "', '"+line_fwfile.strip()+"', '-');"
            cur.execute(sql)
            sql = "INSERT INTO `fwconfig`.`AddressObjects` (`Zone`,`ObjectName`,`FullName`,`IP`,`SubnetMask`,`type`,`comment`, `Firewall`) VALUES ('Global','MIP(" +matchObj_mip.group(2).strip() + ")', '-' ,'"+matchObj_mip.group(2)+"','" +matchObj_mip.group(4).strip() + "',0,'HostIP(" +matchObj_mip.group(3).strip()+ ")' , '"+line_fwfile.strip()+"');"
            cur.execute(sql)
            counter_mip = counter_mip + 1
        elif matchObj_service:
            counter_service = counter_service + 1
            sql = "INSERT INTO fwconfig.services (Service, protocol, `src-port`, `dst-port`, Firewall)VALUES ('"+ matchObj_service.group(1).strip() +"', '"+ matchObj_service.group(2).strip() +"', '"+ matchObj_service.group(3).strip() +"', '"+ matchObj_service.group(4).strip() +"', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
            
        elif matchObj_Scheduler:
            counter_schedular = counter_schedular + 1
            if (matchObj_Scheduler.group(5)):
                sql = "INSERT INTO `fwconfig`.`scheduler` (`Scheduler`,`SchedulerType`,`Start`,`End`,`comment`,`config`, `Firewall`) VALUES ( '"+ matchObj_Scheduler.group(1).strip() +"','"+ matchObj_Scheduler.group(2).strip() +"',STR_TO_DATE('"+ matchObj_Scheduler.group(3).strip() +"','%m/%d/%Y %H:%i'),STR_TO_DATE('"+ matchObj_Scheduler.group(4).strip() +"','%m/%d/%Y %H:%i'),'"+ matchObj_Scheduler.group(6).strip() +"','-', '"+line_fwfile.strip()+"');"
            else :
                sql = "INSERT INTO `fwconfig`.`scheduler` (`Scheduler`,`SchedulerType`,`Start`,`End`,`comment`,`config`, `Firewall`) VALUES ( '"+ matchObj_Scheduler.group(1).strip() +"','"+ matchObj_Scheduler.group(2).strip() +"',STR_TO_DATE('"+ matchObj_Scheduler.group(3).strip() +"','%m/%d/%Y %H:%i'),STR_TO_DATE('"+ matchObj_Scheduler.group(4).strip() +"','%m/%d/%Y %H:%i'),'-','-', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
        elif matchObj_Group:
            if (matchObj_Group.group(3)):
                sql = "INSERT INTO `fwconfig`.`groups` (`Zone`, `GroupName`,  `Comment`, `Firewall` , `type`) VALUES ('" + matchObj_Group.group(1).translate(None, ''.join(charstobreplaced))+ "', '"+matchObj_Group.group(2).translate(None, ''.join(charstobreplaced)) + "', '"+ matchObj_Group.group(4).translate(None, ''.join(charstobreplaced))+"', '" + line_fwfile.strip() + "' , 'address');"
            else :
                sql = "INSERT INTO `fwconfig`.`groups` (`Zone`, `GroupName`,  `Comment`, `Firewall` , `type`) VALUES ('" + matchObj_Group.group(1).translate(None, ''.join(charstobreplaced))+ "', '"+matchObj_Group.group(2).translate(None, ''.join(charstobreplaced)) + "', '-', '" +line_fwfile.strip()+ "', 'address');"   
            cur.execute(sql)
            counter_Group = counter_Group + 1
            
        elif matchObj_Group_member:
            sql = "INSERT INTO `fwconfig`.`group_members` (`GroupName`, `AddressMember`, `Zone`, `Firewall` , `type`) VALUES ('"+matchObj_Group_member.group(2).translate(None, ''.join(charstobreplaced))+"', '"+matchObj_Group_member.group(3).translate(None, ''.join(charstobreplaced))+"', '"+matchObj_Group_member.group(1)+"', '" +line_fwfile.strip()+ "', 'address');"
            cur.execute(sql)
            counter_grp_member = counter_grp_member + 1
            
        elif matchObj_Group_service:
            if (matchObj_Group_service.group(2)):
                sql = "INSERT INTO `fwconfig`.`groups` (`Zone`, `GroupName`,  `Comment`, `Firewall` , `type`) VALUES ('-', '"+matchObj_Group_service.group(1).translate(None, ''.join(charstobreplaced)) + "', '"+ matchObj_Group_service.group(4).translate(None, ''.join(charstobreplaced))+"', '" + line_fwfile.strip() + "' , 'service');"
            else :
                sql = "INSERT INTO `fwconfig`.`groups` (`Zone`, `GroupName`,  `Comment`, `Firewall` , `type`) VALUES ('-', '"+matchObj_Group_service.group(1).translate(None, ''.join(charstobreplaced)) + "', '-', '" +line_fwfile.strip()+ "', 'service');"
            cur.execute(sql)
            counter_Group_srv = counter_Group_srv + 1
            
        elif matchObj_Group_service_member:
            sql = "INSERT INTO `fwconfig`.`group_members` (`GroupName`, `AddressMember`, `Zone`, `Firewall` , `type`) VALUES ('"+matchObj_Group_service_member.group(1).translate(None, ''.join(charstobreplaced))+"', '"+matchObj_Group_service_member.group(2).translate(None, ''.join(charstobreplaced))+"', '-', '" +line_fwfile.strip()+ "', 'service');"
            cur.execute(sql)
            counter_grp_member_srv = counter_grp_member_srv + 1
            
    pass # First inner loop
    print "\nCounter >>>> " , counter
    print "Counter_mip >>>> " , counter_mip
    print "Counter_service >>>> " , counter_service
    print "Counter_schedular >>>> " ,counter_schedular
    print "Counter_Group_Address >>>> " ,counter_Group
    print "Counter_Group_Members >>>> " ,counter_grp_member
    print "Counter_Group_Service >>>> " ,counter_Group_srv
    print "Counter_Group_Service_Memeber >>>> " ,counter_grp_member_srv
    
    # The below code is using the Python logging module to output debug messages. It is logging the number
    # of matches for different types of objects (Address Objects, Service Objects, MIPs, Scheduler
    # Objects, Address Groups, Address Group Members, Service Groups, and Service Group Members) in a
    # firewall configuration file. The `line_fwfile.strip()` is used to remove any leading or trailing
    # whitespaces from the `line_fwfile` variable before concatenating it with the log message. The
    # `str(counter)` and `str(counter_service)` are used to convert the counter variables to strings
    # before concatenating them with
    logger.debug("Address Objects match in firewall  " + line_fwfile.strip() + " = " + str(counter))
    logger.debug("Services Objects match in firewall  " + line_fwfile.strip() + " = " + str(counter_service))
    logger.debug("MIPs match in firewall  " + line_fwfile.strip() + " = " + str(counter_mip))
    logger.debug("Schedular Objects match in firewall  " + line_fwfile.strip() + " = " + str(counter_schedular))
    logger.debug("Address Groups match in firewall  " + line_fwfile.strip() + " = " + str(counter_Group))
    logger.debug("Address Groups members match in firewall  " + line_fwfile.strip() + " = " + str(counter_grp_member))
    logger.debug("Service Groups match in firewall  " + line_fwfile.strip() + " = " + str(counter_Group_srv))
    logger.debug("Service Groups members match in firewall  " + line_fwfile.strip() + " = " + str(counter_grp_member_srv))
    counter_policy = 0
    counter_exit = 0
    
    file_fw_policies = open(tempstr)
    policy_id = '' 
    policy_found = False
    
    # This Python code snippet is reading lines from a file containing firewall policies and extracting
    # information from each line using regular expressions. Here is a breakdown of what the code is doing:
    while 1:
        line_policies = file_fw_policies.readline()
        matchObj_policy = re.match(r'set\spolicy\sid\s(\w*)(\sname\s"([^"]*)")?\sfrom\s"([^"]*)"\sto\s"([^"]*)"\s*"([^"]*)"\s"([^"]*)"\s"([^"]*)"\s((?:nat\ssrc\s)?(?:dip-id\s\d+\s)?)permit(\sschedule\s"([^"]*)")?', line_policies , re.M|re.I)
        matchObj_policy_src = re.match(r'set\ssrc-address\s"([^"]*)"',  line_policies , re.M|re.I )
        matchObj_policy_dst = re.match(r'set\sdst-address\s"([^"]*)"',  line_policies , re.M|re.I )
        matchObj_policy_service = re.match(r'set\sservice\s"([^"]*)"',  line_policies , re.M|re.I )
        matchObj_disable = re.match(r'set\spolicy\sid\s(\w*)\sdisable', line_policies , re.M|re.I)    
        '''
        1:policy ID
        2: name ______
        3: name only
        4:src zone
        5:dst zone
        6:src object
        7:dst object
        8:service
        9:nat src
        10:schedule "Aug_2013"
        11:Aug_2013
        '''
        if matchObj_policy:
            policy_id = matchObj_policy.group(1).strip()
            policy_found = True
            #print "\npolicy id found >>>>>>>>" + policy_id
            counter_policy = counter_policy + 1
            if (matchObj_policy.group(10)):
                if (matchObj_policy.group(2)):
                    sql = "INSERT INTO `fwconfig`.`policies` (`PolicyID`,`PolicyName`,`src_zone`,`dst_zone`,`schedule`, `Firewall` , `NAT`) VALUES (CONVERT('"+ matchObj_policy.group(1).strip() +"', UNSIGNED INTEGER),'"+ matchObj_policy.group(3).strip().translate(None, ''.join(charstobreplaced)) +"','"+ matchObj_policy.group(4).strip() +"','"+ matchObj_policy.group(5).strip() +"','"+ matchObj_policy.group(11).strip() +"', '"+line_fwfile.strip()+"' , ' " +matchObj_policy.group(9).strip() +"');"
                else :
                    sql = "INSERT INTO `fwconfig`.`policies` (`PolicyID`,`PolicyName`,`src_zone`,`dst_zone`,`schedule`, `Firewall` , `NAT` ) VALUES (CONVERT('"+ matchObj_policy.group(1).strip() +"', UNSIGNED INTEGER),'-','"+ matchObj_policy.group(4).strip() +"','"+ matchObj_policy.group(5).strip() +"','"+ matchObj_policy.group(11).strip() +"', '"+line_fwfile.strip()+"', ' " +matchObj_policy.group(9).strip() +"');"
            else :
                if (matchObj_policy.group(2)):
                    sql = "INSERT INTO `fwconfig`.`policies` (`PolicyID`,`PolicyName`,`src_zone`,`dst_zone`,`schedule`, `Firewall` , `NAT`) VALUES (CONVERT('"+ matchObj_policy.group(1).strip() +"', UNSIGNED INTEGER),'"+ matchObj_policy.group(3).strip().translate(None, ''.join(charstobreplaced)) +"','"+ matchObj_policy.group(4).strip() +"','"+ matchObj_policy.group(5).strip() +"','-', '"+line_fwfile.strip()+"', ' " +matchObj_policy.group(9).strip() +"');"
                else :
                    sql = "INSERT INTO `fwconfig`.`policies` (`PolicyID`,`PolicyName`,`src_zone`,`dst_zone`,`schedule`, `Firewall` , `NAT`) VALUES (CONVERT('"+ matchObj_policy.group(1).strip() +"', UNSIGNED INTEGER),'-','"+ matchObj_policy.group(4).strip() +"','"+ matchObj_policy.group(5).strip() +"','-', '"+line_fwfile.strip()+"' , ' " +matchObj_policy.group(9).strip() +"');"
           
            cur.execute(sql)
            sql = "INSERT INTO fwconfig.policies_details (policy_id, Pol_detail_type, Object, Firewall)VALUES (CONVERT('"+ policy_id +"', UNSIGNED INTEGER), 'source', '"+ matchObj_policy.group(6).strip().translate(None, ''.join(charstobreplaced)) +"', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
            sql = "INSERT INTO fwconfig.policies_details (policy_id, Pol_detail_type, Object, Firewall)VALUES (CONVERT('"+ policy_id +"', UNSIGNED INTEGER), 'dest', '"+ matchObj_policy.group(7).strip().translate(None, ''.join(charstobreplaced)) +"', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
            sql = "INSERT INTO fwconfig.policies_details (policy_id, Pol_detail_type, Object, Firewall)VALUES (CONVERT('"+ policy_id +"', UNSIGNED INTEGER), 'service', '"+ matchObj_policy.group(8).strip().translate(None, ''.join(charstobreplaced)) +"', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
        elif (matchObj_policy_src and  policy_found):
            sql = "INSERT INTO fwconfig.policies_details (policy_id, Pol_detail_type, Object, Firewall)VALUES (CONVERT('"+ policy_id +"', UNSIGNED INTEGER), 'source', '"+matchObj_policy_src.group(1).strip().translate(None, ''.join(charstobreplaced))+"', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
        elif (matchObj_policy_dst and  policy_found):
            sql = "INSERT INTO fwconfig.policies_details (policy_id, Pol_detail_type, Object, Firewall)VALUES (CONVERT('"+ policy_id +"', UNSIGNED INTEGER), 'dest', '"+matchObj_policy_dst.group(1).strip().translate(None, ''.join(charstobreplaced))+"', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
        elif (matchObj_policy_service and  policy_found): 
            sql = "INSERT INTO fwconfig.policies_details (policy_id, Pol_detail_type, Object, Firewall)VALUES (CONVERT('"+ policy_id +"', UNSIGNED INTEGER), 'service', '"+matchObj_policy_service.group(1).strip().translate(None, ''.join(charstobreplaced)) +"', '"+line_fwfile.strip()+"');"
            cur.execute(sql)
        elif (matchObj_disable and  policy_found):
            counter_disable = counter_disable + 1  
            sql = "INSERT INTO fwconfig.policies_details (policy_id, Pol_detail_type, Object, Firewall)VALUES (CONVERT('"+ policy_id +"', UNSIGNED INTEGER), 'disabled', '-', '"+line_fwfile.strip()+"');"
            cur.execute(sql) 
        elif  (line_policies.strip() == 'exit' and  policy_found): 
            counter_exit = counter_exit + 1  
            policy_found = False
        if not line_policies:
            break
    pass # second inner loop
    
    print "counter_policy >>>> " ,counter_policy
    print "counter_disable >>>> " ,counter_disable
    print "counter_exit >>>> " ,counter_exit
    
    logger.debug("Policies match in firewall  " + line_fwfile.strip() + " = " + str(counter_policy))
    logger.debug("Policies disabled in firewall  " + line_fwfile.strip() + " = " + str(counter_disable))
    
pass # big looooooooop
logger.debug('Conf Files processing starts ends')
db.commit()
cur.close()
db.close ()
