# Prisma Cloud Resource Public IP CSV

Version: *1.0*
Author: *Marc Hobson and Eddie Beuerlein*

### Summary
This script will create a csv file that contains the resource data from the configuration section of the Prsims Cloud
UI. The data in question is the Public IP of each of the following resources:

* EC2
* ELB
* ELBV2
* RDS
* Redshift
* APIGateway
* VPCNATGateway
* (Beta) CloudFront

### Requirements and Dependencies

1. Python 3.7 or newer

2. OpenSSL 1.0.2 or newer

(if using on Mac OS, additional items may be nessessary.)

3. Pip

```sudo easy_install pip```

4. Requests (Python library)

```sudo pip install requests```

5. YAML (Python library)

```sudo pip install pyyaml```

### Configuration

1. Navigate to *config/configs.yml*

2. Fill out your Prisma Cloud username, password, and customer name - if you are the only customer in your account then leave this blank.

### Run

```
python Main.py

```

The output.csv will be created in the folder in which you run Main.py. 
