print "\n" 
print " **** Consistency check for match conditions **** "
 
print "\n"

print " Hello user ! If a flow match condition is encountered, what would you like to do ? "
print "\n"

str = raw_input(" Enter 'yes' to replace the flow rule or 'no' to ignore : ")
str = str.strip()

print "\n"
print "The option you entered is: ", str + "\n"

f= open('/home/rashmi/RYU295/ryu/lib/flow_decision.txt', 'w') 
f.write(str)
f.close()  
