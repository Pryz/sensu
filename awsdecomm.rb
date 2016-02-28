#!/usr/bin/env ruby
#
# Sensu Handler: awsdecommission
#
# This handler will automatically delete clean up old Sensu agents.
#
# Inspired by https://github.com/agent462/sensu-handler-awsdecomm
# enhanced with cross account AWS IAM Roles
#
# How does it work ?
#
# Before deleting a Sensu client, the handler will check the status of the instance based on the instance_id.
# If the status is "terminated" or "shutting_down", it will call the client API.
# See : https://sensuapp.org/docs/latest/api-clients
#
# Configuration:
#
#    {
#      "handlers": {
#        "awsdecommission": {
#          "command": "/etc/sensu/handlers/awsdecomm.rb",
#          "type": "pipe",
#          "severities": [
#            "warning",
#            "critical",
#            "unknown"
#          ]
#        }
#      },
#      "awsdecommission": {
#        "access_key_id": "XXXXXXXXXX",
#        "secret_access_key": "YYYYYYYYYY",
#        "accounts": {
#          { "name": "dev", "role_arn": "arn:aws:iam::123456::role/cross-account-ec2-ro" },
#          { "name": "preprod", "role_arn": "arn:aws:iam::78901::role/cross-account-ec2-ro" }
#        }
#      }
#    }
#
# Input:
#
#   {
#     "client":{
#       "name": "host02",
#       "address": "172.10.10.5",
#       "timestamp": 1326390159,
#       "instance_id": "i-aaaaaaa",
#       "zone": "us-west-2"
#     },
#     "check":{
#       "name": "keepalive",
#       "issued": 1326390169,
#       "output": "No keepalive sent from client for 152203 seconds (>=180)",
#       "status": 2,
#       "interval": 60,
#       "handler": "awsdecommission",
#       "history": [
#         "0",
#         "2"
#       ],
#       "flapping": false
#     },
#     "occurrences": 1,
#     "action": "create"
#   }
#
#
# Dependencies:
#   gem install aws-sdk
#

require 'sensu-handler'
require 'aws-sdk'
require 'timeout'

class AwsDecomm < Sensu::Handler

  def delete_sensu_client
    puts "Sensu client #{@event['client']['name']} is being deleted."
    retries = 1
    begin
      if api_request(:DELETE, "/clients/#{@event['client']['name']}").code != '202' then raise "Sensu API call failed;" end
    rescue StandardError => e
      if (retries -= 1) >= 0
        sleep 3
        puts "Deletion failed; retrying to delete sensu client #{@event['client']['name']} : #{e.message}"
        retry
      else
        puts "Deleting sensu client #{@event['client']['name']} failed permanently."
        send_notification
      end
    end
  end

  def role_arn_for(account_name)
    settings['awsdecommission']['accounts'].each do |account|
        return account['role_arn'] if account['name'] == account_name
    end
  end

  def set_ec2_client
    agent_region = @event['client'].key?("zone") ? @event['client']['zone'].chop! : "us-east-1"
    creds = nil

    unless @event['client'].key? 'aws_account'
      creds = Aws::EC2::Client.new(
        access_key_id: settings['awsdecommission']['access_key_id'],
        secret_access_key: settings['awsdecommission']['secret_access_key'],
        region: agent_region
      )
    else
      begin
        sts_clt = Aws::STS::Client.new(
          access_key_id: settings['awsdecommission']['access_key_id'],
          secret_access_key: settings['awsdecommission']['secret_access_key'],
          region: agent_region
        )

        creds = Aws::AssumeRoleCredentials.new(
          client: sts_clt,
          role_arn: role_arn_for(@event['client']['aws_account']),
          role_session_name: 'sensu'
        )
      rescue StandardError => e
        puts "Error creating Role credentials: #{e.message}"
        exit(-1)
      end
    end

    return Aws::EC2::Client.new(
      :credentials => creds,
      :region => agent_region,
    )
  end

  def check_ec2
    instance = false

    ec2 = set_ec2_client

    retries = 1
    begin
      i = ec2.describe_instance_status({
        :instance_ids => [@event['client']['instance_id']]
      })
      i.instance_statuses.each do |status|
        puts "Instance #{@event['client']['name']} exists; Checking state"
        instance = true
        if status.instance_state.name.to_s === 'terminated' or status.instance_state.name.to_s === 'shutting_down'
          puts "Instance #{@event['client']['name']} is #{status.instance_state.name}; I will proceed with decommission activities."
          delete_sensu_client
        else
          puts "Client #{@event['client']['name']} is #{status.instance_state.name}"
          send_notification
        end
      end
    rescue Aws::Errors::MissingCredentialsError, Aws::Errors::ServiceError => e
      if (retries -= 1) >= 0
        sleep 3
        puts e.message + " AWS lookup for #{@event['client']['name']} has failed; trying again."
        retry
      else
        puts "AWS instance lookup failed for #{@event['client']['name']}."
        send_notification
      end
    end
    if instance == false
      puts "AWS instance was not found #{@event['client']['name']}."
      delete_sensu_client
    end
  end

  def send_notification
    # TODO : Add notifications when we delete a client.
    return
  end

  def handle
    unless @event['client'].key? 'instance_id'
      bail 'AwsDecomm handler require the client `instance_id`'
    end
    if @event['action'].eql?('create')
      check_ec2
    end
  end
end
