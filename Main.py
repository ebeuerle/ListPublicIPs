import lib
import json
import socket

class ListPublicIP():
    def __init__(self):
        self.config = lib.ConfigHelper()
        self.csv_writer = lib.CsvWriter()
        self.rl_sess = lib.RLSession(self.config.rl_user, self.config.rl_pass, self.config.rl_cust,
                                     self.config.rl_api_base)
        ### CSV Configuration ###
        self.output = [["AccountName", "RRN", "Service", "ResourceName", "PublicIP"]]

    def get_AWS_EC2_PublicIPs(self):
        # write out the top of csv to file
        self.csv_writer.write(self.output)

                ###EC2 Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()  # authenticates client

        ec2payload = {"query": "config from cloud.resource where api.name = \"aws-ec2-describe-instances\" AND json.rule = publicIpAddress exists",
                      "timeRange": {"type": "relative", "value": {"unit": "hour", "amount": 24}, "relativeTimeType": "BACKWARD"}}
        ec2publicIpAddress = self.rl_sess.client.post(self.url, json.dumps(ec2payload))
        ec2publicIpAddress_json = ec2publicIpAddress.json()  # convert to JSON

        for awsresource in ec2publicIpAddress_json['data']['items']:
            #Gather all relevant data for EC2 instances
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsec2name = awsresource['name']
            awsservice = awsresource['service']
            awspublicIpAddress = awsresource['data']['publicIpAddress']

            #Gather EC2 data to be added to CSV
            data = [awsaccountName,awsrrn,awsservice,awsec2name,awspublicIpAddress]
            self.csv_writer.append([data])

    def get_AWS_ELBV2_PublicIPs(self):
                ###ELB V2 Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()

        elbpayload = {"query":"config where api.name = 'aws-elbv2-describe-load-balancers' AND json.rule = scheme equals internet-facing",
            "timeRange":{"type":"relative","value":{"unit":"hour","amount":24},"relativeTimeType":"BACKWARD"}}
        elbpublicIpAddress = self.rl_sess.client.post(self.url, json.dumps(elbpayload))
        elbpublicIpAddress_json = elbpublicIpAddress.json()  # convert to JSON

                ###Gather all relevant data for ELB resources
        for awsresource in elbpublicIpAddress_json['data']['items']:
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsservice = awsresource['service']
            awselbname = awsresource['name']

            #Resolve DNS names to IPs
            try:
                awselb_tuple = socket.gethostbyname_ex(awsresource['data']['dnsname'])
                (hostname,alias,awselbresolvedIP) = awselb_tuple #unpack tuple, grab 3rd (IPs) and assign variable (becomes list)
            except socket.gaierror:
                awselbresolvedIP = "Could not resolve"

            s = ", "
            if awselbresolvedIP != "Could not resolve":
                awselbresolvedIP = s.join(awselbresolvedIP)

            data = [awsaccountName,awsrrn,awsservice,awselbname,awselbresolvedIP]
            self.csv_writer.append([data])

    def get_AWS_ELB_PublicIPs(self):
                ###ELB Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()

        elbpayload = {"query":"config where api.name = 'aws-elb-describe-load-balancers' AND json.rule = description.scheme equals internet-facing",
            "timeRange":{"type":"relative","value":{"unit":"hour","amount":24},"relativeTimeType":"BACKWARD"}}
        elbpublicIpAddress = self.rl_sess.client.post(self.url, json.dumps(elbpayload))
        elbpublicIpAddress_json = elbpublicIpAddress.json()  # convert to JSON

                ###Gather all relevant data for ELB resources
        for awsresource in elbpublicIpAddress_json['data']['items']:
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsservice = awsresource['service']
            awselbname = awsresource['name']

            #Resolve DNS names to IPs
            try:
                awselb_tuple = socket.gethostbyname_ex(awsresource['data']['description']['dnsname'])
                (hostname,alias,awselbresolvedIP) = awselb_tuple #unpack tuple, grab 3rd (IPs) and assign variable (becomes list)
            except socket.gaierror:
                awselbresolvedIP = "Could not resolve"

            s = ", "
            if awselbresolvedIP != "Could not resolve":
                awselbresolvedIP = s.join(awselbresolvedIP)

            data = [awsaccountName,awsrrn,awsservice,awselbname,awselbresolvedIP]
            self.csv_writer.append([data])

    def get_AWS_RDS_PublicIPs(self):
        ###RDS Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()

        rdspayload = {"query":"config where cloud.type = 'aws' AND api.name = 'aws-rds-describe-db-instances' and json.rule = publiclyAccessible is true as X; config where api.name = 'aws-ec2-describe-route-tables' as Y; filter \"($.Y.associations[*].subnetId exists and $.X.dbsubnetGroup.subnets[*].subnetIdentifier contains $.Y.associations[*].subnetId) and ($.Y.routes[*].gatewayId exists and $.Y.routes[?(@.destinationCidrBlock == '0.0.0.0/0')].gatewayId contains igw)\"; show X;",
            "timeRange":{"type":"relative","value":{"unit":"hour","amount":24},"relativeTimeType":"BACKWARD"}}
        rdspublicIpAddress = self.rl_sess.client.post(self.url, json.dumps(rdspayload))
        rdspublicIpAddress_json = rdspublicIpAddress.json()  # convert to JSON

                ###Gather all relevant data for RDS resources
        for awsresource in rdspublicIpAddress_json['data']['items']:
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsservice = awsresource['service']
            awsrdsname = awsresource['name']

            #Resolve DNS names to IPs
            try:
                awsrds_tuple = socket.gethostbyname_ex(awsresource['data']['endpoint']['address'])
                (hostname,alias,awsrdsresolvedIP) = awsrds_tuple #unpack tuple, grab 3rd (IPs) and assign variable (becomes list)
            except socket.gaierror:
                awsrdsresolvedIP = "Could not resolve"

            s = ", "
            if awsrdsresolvedIP != "Could not resolve":
                awsrdsresolvedIP = s.join(awsrdsresolvedIP)

            data = [awsaccountName,awsrrn,awsservice,awsrdsname,awsrdsresolvedIP]
            self.csv_writer.append([data])

    def get_AWS_RED_PublicIPs(self):
        ###Redshift Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()

        redpayload = {"query":"config where cloud.type = 'aws' AND api.name = 'aws-redshift-describe-clusters' AND json.rule = publiclyAccessible is true",
            "timeRange":{"type":"relative","value":{"unit":"hour","amount":24},"relativeTimeType":"BACKWARD"}}
        rdspublicIpAddress = self.rl_sess.client.post(self.url, json.dumps(redpayload))
        rdspublicIpAddress_json = rdspublicIpAddress.json()  # convert to JSON

                ###Gather all relevant data for Redshift resources
        for awsresource in rdspublicIpAddress_json['data']['items']:
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsservice = awsresource['service']
            awsredname = awsresource['name']

            #Resolve DNS names to IPs
            try:
                awsred_tuple = socket.gethostbyname_ex(awsresource['data']['endpoint']['address'])
                (hostname,alias,awsredresolvedIP) = awsred_tuple #unpack tuple, grab 3rd (IPs) and assign variable (becomes list)
            except socket.gaierror:
                awsredresolvedIP = "Could not resolve"

            s = ", "
            if awsredresolvedIP != "Could not resolve":
                awsredresolvedIP = s.join(awsredresolvedIP)

            data = [awsaccountName,awsrrn,awsservice,awsredname,awsredresolvedIP]
            self.csv_writer.append([data])

    def get_AWS_CloudFront_PublicIPs(self):
        ###CloudFront Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()

        redpayload = {"query":"config where api.name = 'aws-cloudfront-list-distributions'",
            "timeRange":{"type":"relative","value":{"unit":"hour","amount":24},"relativeTimeType":"BACKWARD"}}
        rdspublicIpAddress = self.rl_sess.client.post(self.url, json.dumps(redpayload))
        rdspublicIpAddress_json = rdspublicIpAddress.json()  # convert to JSON

                        ###Gather all relevant data for CloudFront resources
        for awsresource in rdspublicIpAddress_json['data']['items']:
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsservice = awsresource['service']
            awscfname = awsresource['name']

            # Resolve DNS names to IPs
            try:
                for domainnames in awsresource['data']['origins']['items']:
                    domainname = domainnames['domainName']
                    awsred_tuple = socket.gethostbyname_ex(domainname)
                    (hostname, alias,awsredresolvedIP) = awsred_tuple  # unpack tuple, grab 3rd (IPs) and assign variable (becomes list)

            except  socket.gaierror:
                awsredresolvedIP = "Could not resolve"

            s = ", "
            if awsredresolvedIP != "Could not resolve":
                awsredresolvedIP = s.join(awsredresolvedIP)

            data = [awsaccountName,awsrrn,awsservice,awscfname,awsredresolvedIP]
            self.csv_writer.append([data])

    def get_AWS_APIGateway_PublicIPs(self):
                ###API Gateway Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()

        APIGatewayPayload = {"query": "config where api.name = 'aws-apigateway-domain-name'",
            "timeRange": {"type": "relative", "value": {"unit": "hour", "amount": 24}, "relativeTimeType": "BACKWARD"}}
        apigwpublicIpAddress = self.rl_sess.client.post(self.url, json.dumps(APIGatewayPayload))
        apigwpublicIpAddress_json = apigwpublicIpAddress.json()  # convert to JSON

        ###Gather all relevant data for ELB resources
        for awsresource in apigwpublicIpAddress_json['data']['items']:
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsservice = awsresource['service']
            awsapigwname = awsresource['name']

            # Resolve DNS names to IPs
            try:
                awsapigw_tuple = socket.gethostbyname_ex(awsresource['data']['regionalDomainName'])
                (hostname, alias,
                 awsapigwresolvedIP) = awsapigw_tuple  # unpack tuple, grab 3rd (IPs) and assign variable (becomes list)
            except socket.gaierror:
                awsapigwresolvedIP = "Could not resolve"
            except:
                print('{} had an issue with it\'s regionalDomainName configuration'.format(awsresource))

            s = ", "
            if awsapigwresolvedIP != "Could not resolve":
                awsapigwresolvedIP = s.join(awsapigwresolvedIP)

            data = [awsaccountName, awsrrn, awsservice, awsapigwname, awsapigwresolvedIP]
            self.csv_writer.append([data])

    def get_AWS_VPCNATGateway_PublicIPs(self):
                ###VPC NAT Gateway Public IPs###
        self.url = "https://" + self.config.rl_api_base + "/search/config"  # search using RQL
        self.rl_sess.authenticate_client()

        VPCNATGatewayPayload = {"query": "config where api.name = 'aws-vpc-nat-gateway'",
            "timeRange": {"type": "relative", "value": {"unit": "hour", "amount": 24}, "relativeTimeType": "BACKWARD"}}
        vpcnatgwpublicIpAddress = self.rl_sess.client.post(self.url, json.dumps(VPCNATGatewayPayload))
        vpcnatgwpublicIpAddress_json = vpcnatgwpublicIpAddress.json()  # convert to JSON

        ###Gather all relevant data for ELB resources
        for awsresource in vpcnatgwpublicIpAddress_json['data']['items']:
            awsaccountName = awsresource['accountName']
            awsrrn = awsresource['rrn']
            awsservice = awsresource['service']
            awsvpcnatgwname = awsresource['name']

            # Resolve DNS names to IPs
            try:
                for publicIps in awsresource['data']['natGatewayAddresses']:
                    publicIp = publicIps['publicIp']
                    awsred_tuple = socket.gethostbyname_ex(publicIp)
                    (hostname, alias,awsvpcnatgwresolvedIP) = awsred_tuple  # unpack tuple, grab 3rd (IPs) and assign variable (becomes list)

            except  socket.gaierror:
                awsvpcnatgwresolvedIP = "Could not resolve"

            s = ", "
            if awsvpcnatgwresolvedIP != "Could not resolve":
                awsvpcnatgwresolvedIP = s.join(awsvpcnatgwresolvedIP)

            data = [awsaccountName, awsrrn, awsservice, awsvpcnatgwname, awsvpcnatgwresolvedIP]
            self.csv_writer.append([data])

    def run(self):
        #Make sure to add all FUNCTIONS here!!!###
        self.get_AWS_EC2_PublicIPs()
        self.get_AWS_ELBV2_PublicIPs()
        self.get_AWS_ELB_PublicIPs()
        self.get_AWS_RDS_PublicIPs()
        self.get_AWS_RED_PublicIPs()
        self.get_AWS_APIGateway_PublicIPs()
        self.get_AWS_VPCNATGateway_PublicIPs()

        #Optional(BETA)
        #self.get_AWS_CloudFront_PublicIPs() #Uncomment to resolve S3 buckets serving CloudFront

def main():
    pc_listpublicip = ListPublicIP()
    pc_listpublicip.run()



if __name__ == "__main__":
    main()