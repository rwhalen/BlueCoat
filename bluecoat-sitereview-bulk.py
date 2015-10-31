#!/usr/bin/env python
#
# bluecoat-sitereview-bulk.py
# Ryan Whalen (rwhalen)
# 
# Overview:
#    Read a file full of URLs and bulk submit them for review to BlueCoat SiteReview. If
#    the URL classification matches a category defined in the BLOCKED_CATEGORIES list, it 
#    will not be submitted for review.  Otherwise, the category passed to the script with
#    the -c / --category argument will be used as the suggested category.
#
# Example:
#    python bluecoat-sitereview-bulk.py -f urls.txt -c 1 -e emailaddr@gmail.com
#

import sys
import getopt
import re
import requests
import simplejson
import time

VERIFY_SSL = True      # Change this to False if you do not want to verify SSL Certificates.
TIMEWAIT = 5           # Time in seconds to wait between submissions. 

'''
Use the BLOCKED_CATEGORIES list to list the names of categories that your organization is already blocking.
If a URL that you are checking is already classified as one of your blocked categories, the script will not
re-submit the URL to BlueCoat SiteReview for re-classification.
'''      
BLOCKED_CATEGORIES = ['Suspicious', 'Malicious Sources/Malnets', 'Spam', 'Phishing', 'Potentially Unwanted Software',
                      'Adult/Mature Content']



def main(argv):

    input_file = ''
    email_addr = ''
    recat = ''

    try:
        opts, args = getopt.getopt(argv,"hf:c:e:",["file=","category=","email="])
    except getopt.GetoptError:
        sys.exit(usage())
    for opt, arg in opts:
        if opt == '-h':
            sys.exit(usage())
        elif opt in ("-f", "--file"):
            input_file = arg.lower()
        elif opt in ("-c", "--category"):
            recat = arg.lower()
        elif opt in ("-e", "--email"):
            email_addr = arg

    '''
    The suggested_category value is the value defined in the site review submission form for each
    category type.  I mapped a few of the more common recategorization values here.
    '''
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
    else:
        sys.exit(usage())    
        
    if (email_addr != ''):
        email_checkbox_status = 'on'

    try:
        with open(input_file, 'r') as f:
            urls = f.readlines()
    except:
        print '[!] Error reading file %s\n\n' %(input_file)
        usage()
        sys.exit(1)
        
    
    
    '''
    Mappings used to translate command line arguments to friendly category name
    '''
    category_mappings = {'1':'Malicious Sources',
                          '2':'Phishing',
                          '3':'Potentially Unwanted Software',
                          '4':'Spam',
                          '5':'Suspicious' }

    cat_status_url = 'https://sitereview.bluecoat.com/rest/categorization'              #URL used to check current categorization status
    submit_cat_url = 'https://sitereview.bluecoat.com/rest/submitCategorization'        #URL used to submit new category recommendation

    s = requests.session()

    headers = {'X-Requested-With':'XMLHttpRequest', 
               'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
                   (KHTML, like Gecko) Chrome/44.0.2403.107 Safari/537.36', 
                                                                          'Origin':'https://sitereview.bluecoat.com',
                                                                          'Referer':'https://sitereview.bluecoat.com/sitereview.jsp'}
    
        
    for url in urls:
        u = url.strip()
        if is_valid_url(u):

            check_status_payload = 'url=%s' % (u)                                           #Payload for our HTTP POST checking the current category status
            r = s.post(cat_status_url,headers=headers,data=check_status_payload,verify=VERIFY_SSL)      #Generate HTTP POST to check current category status
        
            response_dict = simplejson.loads(r.text)
        
            submission_error = response_dict.get("error", {})
            current_categorization = response_dict.get("categorization", {})    #Current categorization results (needs to be parsed to clean up category name)
            tracking_id = response_dict.get("curtrackingid", {})                #Tracking ID associated with the request (required to submit category change)
            is_unrated = response_dict.get("unrated", {})                       #Flag indicating the URL is unrated.  
            ratedate = response_dict.get("ratedate", {})
            
            
            if submission_error:
                print '[!] - Error submitting %s -- skipping\n\t%s' % (u[0:40],submission_error)
                continue
            
            current_category_1 = ''
            current_category_2 = ''
            
            if (is_unrated == 'True'):
                current_category = 'Unrated'
                
            if re.match("^.+\>(.+)\<\/a>\sand\s.+\>(.+)\<.+",current_categorization):
                current_category_1 = re.match("^.+\>(.+)\<\/a>\sand\s.+\>(.+)\<.+",current_categorization).group(1)
                current_category_2 = re.match("^.+\>(.+)\<\/a>\sand\s.+\>(.+)\<.+",current_categorization).group(2)
            elif re.match("^.+\>(.+)\<.+", current_categorization):
                current_category_1 = re.match("^.+\>(.+)\<.+", current_categorization).group(1)
            else:
                print '[!] Error: Unexpected data returned for current categorization...exiting!'
                print '\t%s' %(current_categorization)
                sys.exit(1)
   
            
            if(current_category_1 in BLOCKED_CATEGORIES or current_category_2 in BLOCKED_CATEGORIES):
                print '[*] %s is already blocked (%s) -- skipping' % (u[0:40],current_category_1+','+current_category_2)
                time.sleep(TIMEWAIT)
            else:
                print '[*] %s is classified as (%s)' % (u[0:40],current_category_1+','+current_category_2)
                print '\t[*] Submitting request to categorize %s as %s' % (u[0:40],category_mappings[recat])
   
                recat_payload = 'referrer=bluecoatsg&suggestedcat=%s&suggestedcat2=&emailCheckBox=%s&email=%s&emailcc=&comments=&overwrite=no&trackid=%s' \
                    % (suggested_category,email_checkbox_status,email_addr,tracking_id)
              
                r = s.post(submit_cat_url,headers=headers,data=recat_payload,verify=VERIFY_SSL)           #Generate HTTP POST to recategorize URL
                response_dict = simplejson.loads(r.text)
                submission_message = response_dict.get("message",{})
                
                if (str(r.status_code) == '200' and submission_message[0:38] == 'Your page submission has been received'):
                    print '\t[*] Request submitted:  %s (%s) => %s' % (u[0:40], current_category, category_mappings[recat])
                else:
                    print '\t[!] An error occured during submission (HTTP Code%s)' % (r.status_code)
                    print '\t[!] %s' % (submission_message)

                time.sleep(TIMEWAIT)

    return()


def is_valid_url(url):
    import re
    regex = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url is not None and regex.search(url)
    
def usage():
    print 'Usage:\tbluecoat-sitereview-bulk.py -f [file] -c [category index] -e [email_address]\n\nExample: \
    bluecoat-sitereview-bulk.py -f urls_to_check.txt -c 1 -e my_email_address@gmail.com\n\nCategory Index Options:\n1:\tMalicious Sources\n2:\tPhishing\n3:\tPotentially Unwanted Software\n4:\tSpam\n5:\tSuspicious\n\n'
    

if __name__ == '__main__':
    main(sys.argv[1:])