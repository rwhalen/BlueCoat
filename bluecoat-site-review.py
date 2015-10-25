#!/usr/bin/env python
#
# bluecoat-site-review.py
# Ryan Whalen (rwhalen)
# Submit a URL for review/reclassification
#
#

import sys
import getopt
import re
import requests
import simplejson

def main(argv):
    
    input_url = ''      #URL we are searching / recategorizing
    recat = ''          #Suggested category for URL
    email_addr = ''     #Email address for receiving submission results.
    category_mappings = {'1':'Malicious Sources',
                         '2':'Phishing',
                         '3':'Potentially Unwanted Software',
                         '4':'Spam',
                         '5':'Suspicious' }
    
    try:
        opts, args = getopt.getopt(argv,"hu:c:e:",["url=","category=","email="])
    except getopt.GetoptError:
        sys.exit(usage())
    for opt, arg in opts:
        if opt == '-h':
            sys.exit(usage())
        elif opt in ("-u", "--url"):
            input_url = arg.lower()
        elif opt in ("-c", "--category"):
            recat = arg.lower()
        elif opt in ("-e", "--email"):
            email_addr = arg
    
    if (input_url ==''):
        sys.exit(usage())

    cat_status_url = 'https://sitereview.bluecoat.com/rest/categorization'              #URL used to check current categorization status
    submit_cat_url = 'https://sitereview.bluecoat.com/rest/submitCategorization'        #URL used to submit new category recommendation
    
    s = requests.session()
    
    headers = {'X-Requested-With':'XMLHttpRequest', 
               'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
               (KHTML, like Gecko) Chrome/44.0.2403.107 Safari/537.36', 
               'Origin':'https://sitereview.bluecoat.com',
               'Referer':'https://sitereview.bluecoat.com/sitereview.jsp'}

    check_status_payload = 'url=%s' % (input_url)                                           #Payload for our HTTP POST checking the current category status
    r = s.post(cat_status_url,headers=headers,data=check_status_payload)      #Generate HTTP POST to check current category status
    
    response_dict = simplejson.loads(r.text)
    
    current_categorization = response_dict.get("categorization", {})    #Current categorization results (needs to be parsed to clean up category name)
    tracking_id = response_dict.get("curtrackingid", {})                #Tracking ID associated with the request (required to submit category change)
    is_unrated = response_dict.get("unrated", {})                       #Flag indicating the URL is unrated.
    
    if (is_unrated == 'true'):
        current_category = 'Unrated'
    else:
        try:
            match = re.match("^.+\>(.+)\<.+", current_categorization)
            current_category = match.group(1)
        except:
            sys.exit(1)  
    
    if (recat == ''):    #If we didn't specify a category in the command line arguments, prompt the user for the new category
        print 'URL: %s\nCurrent Category: %s\n' % (input_url, current_category)
        recat = raw_input('How would you like to reclassify this URL?\n1) Malicious Sources\n2) Phishing\n3) Potentially Unwanted Software\n4) Spam\n5) Suspicious\n0) Exit\n\nEnter Choice >') 

    if (email_addr != ''):
        email_checkbox_status = 'on'
    else:
        email_results = raw_input('Enter email address to use for results [none] >')
        if email_results =='':
            email_checkbox_status = 'off'
        else:
            email_checkbox_status = 'on'
            email_addr = email_results
        
    if recat == '1':                #Malicious Sources
        suggested_category = '43'
    elif recat == '2':              #Phishing
        suggested_category = '18'
    elif recat == '3':              #Potentially Unwanted Software
        suggested_category = '102' 
    elif recat == '4':              #Spam
        suggested_category = '101'
    elif recat == '5':              #Suspicious
        suggested_category = '92'
    elif recat == '0':
        sys.exit(0)
    else:
        sys.exit(usage())
          
    recat_payload = 'referrer=bluecoatsg&suggestedcat=%s&suggestedcat2=&emailCheckBox=%s&email=%s&emailcc=&comments=&overwrite=no&trackid=%s' \
        % (suggested_category,email_checkbox_status,email_addr,tracking_id)
  
    r = s.post(submit_cat_url,headers=headers,data=recat_payload)           #Generate HTTP POST to recategorize URL
    
    if str(r.status_code) == '200':                                         #We are expecting an HTTP Response Code 200 (OK)
        print '\n[*] Submission Successful.'
        print '\t[*] URL: %s' % (input_url)
        print '\t[*] Original Category: %s' % (current_category)
        print '\t[*] Requested Category: %s' % (category_mappings[recat])
    else:
        print '\n\n[!] An error occured during submission (HTTP %s)' % (r.status_code)


def usage():
    print 'Usage:\tbluecoat-site-review.py -u [URL] -c [category index] -e [email_address]\n\nExample: \
    bluecoat-site-review.py -u http://www.badsite.com -c 1 -e my_email_address@gmail.com\n\nCategory Index Options:\n1:\tMalicious Sources\n2:\tPhishing\n3:\tPotentially Unwanted Software\n4:\tSpam\n5:\tSuspicious\n\n'


if __name__ == '__main__':
    main(sys.argv[1:])