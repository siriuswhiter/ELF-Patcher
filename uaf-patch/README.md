# Note

  Use_after_free Vulnerabilities are common in CTF,and sometimes we were asked to fix it without source code ,such as CISCN.

  Maybe this little tool can help you to fix it quickly.

# Method

  I'm trying to write a new "free" function,which can clear off the ptr.

  But this requires that the parameter be a pointer to the pointer,while the common "free" just has the pointer.

  So I write the new "free" function as hook,which will be added to the main file's .LOAD.section.

  For more convenience,I add the function about migrating code.

  You can specify the starting address and the ending address,then this segment will be migrated to .LOAD.section.(!!You have to be careful with come functions just as "call" or "jmp" because it uses offset to calculate location rather than absolute address.)

  Then there will be some extra "nop" in old poistion.What you should do is make '$rdi=[$rdi].'

# Usage

  '''
  python patch2.py <binname> <CallFreeAddress>
  '''
  
  then use IDA to edit it make parameter change from ptr to *ptr.


  
