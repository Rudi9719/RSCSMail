 
/* REXX */
parse upper arg params . '(' options
 
/* Set NODE to your RSCS SMTP Node and SMTP to the NJE Run As User */
NODE='PUBNET'
SMTP='SMTP'
 
if params<>'' then do
 SAY 'To invoke the MAIL EXEC, use one of the following incantations:'
 SAY '  MAIL (PROFS : To prepare a NOTE through SMTP using PROFS'
 SAY '  MAIL (CMS   : To prepare a NOTE through SMTP using the CMS NOTE'
 SAY '  MAIL ?      : To show this preamble  '
 SAY ''
 SAY ' For more info: HELP MAIL  '
 exit 0
end
 
if options=='PROFS' then do
 address command
 'PROFS NOTE to 'NODE'('SMTP')'
 exit rc
end
 
'EXEC NOTE 'SMTP' AT 'NODE
exit rc