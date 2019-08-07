# turbo-waffle
This is a tool to automate classifying and blocking IP Addresses

Using the AbuseIPDB api, this program will look at the Abuse Confidence Score (ACS).
This number can range from 0-100. If this number has ACS of more than 30 the IP
will appended to a list to be emailed to the NOC to have them block the IP address
on our load balancers this will also be added to the blocked IP text file so only
unique IP addresses are blocked. If the score is less than 30, the IP address will 
be emailed to the IT Security team to review.

## Installation
this is built to be run along side a sumo logic script action. Put abuseipdb_ref.py
into a new folder and point the list_of_files variable from the get_latest_file
function to your alerts.

### Usage
Once installed, create a cron job to run the abuseipdb.py script every time a new
script action alert comes in. This will allow an instant action to take place. Also,
set up another cron job to delete the IP adddresses added to the blocked IP file to
make sure repeat offenders are not forgotten about.
