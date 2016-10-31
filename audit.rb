############################
# https://github.com/Trouiller-David
############################
# encoding: Windows-1252
#????????????????????????????????????????????????????????????????????????????????????
distribution = "C:/xampp/htdocs"
server = "localhost"
#????????????????????????????????????????????????????????????????????????????????????
original = "cms"
backup = "backup-cms"
#????????????????????????????????????????????????????????????????????????????????????
strings = <<STRINGS
<apache_server_version>
<mysql_server_version>
<mysql_fork_version>
<openssl_version>
<php_version>
xampp/htdocs
xampp\htdocs
<computer_username>
<computer_name>
<database_password>
<database_name>
<database_prefix>
<website_username>
<website_password>
<website_email>
<website_version>
STRINGS
#????????????????????????????????????????????????????????????????????????????????????
#====================================================================================
require('securerandom')
require('mechanize')
agent = Mechanize.new()
agent.read_timeout = 60
agent.open_timeout = 60
agent.keep_alive = false 
agent.redirect_ok = false
agent.agent.http.verify_mode = OpenSSL::SSL::VERIFY_NONE
agent.request_headers = {"Referer" => "", "Accept" => "*/*"}
#||
proxy = Mechanize.new()
proxy.read_timeout = 10
proxy.open_timeout = 10
proxy.keep_alive = false 
proxy.redirect_ok = false
proxy.set_proxy("127.0.0.1", "8080")
proxy.agent.http.verify_mode = OpenSSL::SSL::VERIFY_NONE
proxy.request_headers = {"Referer" => "", "Accept" => "*/*"}
#====================================================================================
#////////////////////////////////////////////////////////////////////////////////////
rpath = Dir.getwd()
common = rpath.gsub(distribution, "")
rurl = "http://"+server+common+"/"
rpath = rpath+"/"
banner = <<BANNER
#{"%"*60}
# URL => #{rurl}
# PATH => #{rpath}
#{"%"*60}
BANNER
puts(banner)
#////////////////////////////////////////////////////////////////////////////////////
#####################################################################################
def folders(rurl,agent)
banner = <<BANNER
#{"!"*60}
# Module Folders Scanning
#{"!"*60}
BANNER
puts(banner)
#
i=0
Dir.glob("**/*/").each() do |folder|
begin
url = rurl+folder
response = agent.get(url)
body = response.body()
length = response.body().length()
rescue Exception => e
if(e.inspect().include?("Net::HTTP::Persistent") == false && e.inspect().include?("Net::HTTPForbidden") == false && e.page().body().empty?() == false)
error = <<ERROR
#{"="*30}
[-] #{e.inspect()}
[*] #{e.page().body().inspect()}
#{"="*30}
ERROR
puts(error)
end
else
if(body.empty?() == false && body.include?("<title>Index of") == true && body.include?("<h1>Index of") == true)
result = <<RESULT
[INDEX] intitle:("Index Of") AND inurl:("#{folder}") {#{length} bytes}
RESULT
puts(result)
end
end
i+=1
end
end
#####################################################################################
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
def files(rurl,agent,proxy,strings,rpath)
banner = <<BANNER

#{"!"*60}
# Module Files Scanning
#{"!"*60}
BANNER
puts(banner)
#
Dir.glob("**/*.*").each() do |file|
if(file.match(/\.(rb|ico|bmp|png|jpg|gif|rar|zip|gz|bz2|ttf|otf|woff|woff2|eot|svg|swf|fdb|wav|swf|mp3)$/).inspect().include?("MatchData") == false)
begin
url = rurl+file
response = agent.get(url)
body = response.body().inspect()
rescue Exception => e
if(e.inspect().include?("Net::HTTP::Persistent") == false && e.inspect().include?("Net::HTTPForbidden") == false && e.page().body().empty?() == false)
error = <<ERROR
#{"="*30}
[-] #{e.inspect()}
[*] #{e.page().body().inspect()}
#{"="*30}
ERROR
puts(error)
end
else
if(body.empty?() == false)
begin
title = response.title()
if(title.nil?() == false)
result = <<RESULT
[TITLE] intitle:(#{title.inspect()}) AND inurl:("#{file}")
RESULT
puts(result)
end
rescue
end
begin
form = response.forms()
if(form.empty?() == false)
result = <<RESULT
[FORM] #{url}
#{form.inspect()}
RESULT
puts(result)
begin
proxy.get(url)
rescue
end
end
rescue
end
strings.split("\n").each() do |string|
if(body.include?(string) == true)
result = <<RESULT
[#{string.inspect()}] #{url}
RESULT
puts(result)
end
end
end
end
#||
begin
path = rpath+file
read = File.new(path, "r+").read()
rescue
else
if(read.empty?() == false)
strings.split("\n").each() do |string|
if(read.include?(string) == true)
result = <<RESULT
[#{string.inspect()}] #{path}
RESULT
puts(result)
end
end
end
end
#||
end
end
end
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
def extension()
banner = <<BANNER

#{"!"*60}
# Module Extensions Scanning
#{"!"*60}
BANNER
puts(banner)
#
array = []
begin
Dir.glob("**/*.*").each() do |filename|
array << File.extname(filename)
end
rescue
end
array.uniq().each() do |extname|
i=0
begin
Dir.glob("**/*"+extname).each() do |type|
i+=1
end
rescue
end
puts("["+extname+"]"+" == "+i.to_s())
end
end
#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
#------------------------------------------------------------------------------------
def audit(rurl,rpath,agent,proxy)
banner = <<BANNER

#{"!"*60}
# Module PHP Scanning
#{"!"*60}
BANNER
puts(banner)
#
Dir.glob("**/*.php").each() do |php|
begin
url = rurl+php
path = rpath+php
response = agent.post("http://localhost/rips/main.php", {
"loc"=>path,
"subdirs"=>0,
"verbosity"=>1,
"vector"=>"all",
"treestyle"=>1,
"stylesheet"=>"ayti"
})
body = response.body().inspect().gsub(/\[\]/, "").gsub(/\[\*\]/, "").gsub(/\[\=/, "[")
rescue Exception => e
error = <<ERROR
[-] #{e.inspect()}
ERROR
puts(error)
else
get = ""
body.scan(Regexp.union(/\<td nowrap\>\$_GET\[(.+?)\]\<\/td\>/)).uniq().each() do |variable|
get+=variable.compact().join()+"=&"
end
get = get.chomp("&")
#||
request = ""
body.scan(Regexp.union(/\<td nowrap\>\$_REQUEST\[(.+?)\]\<\/td\>/,/\<td nowrap\>\$HTTP_REQUEST_VARS\[(.+?)\]\<\/td\>/)).uniq().each() do |variable|
request+=variable.compact().join()+"=&"
end
request = request.chomp("&")
#||
post = ""
body.scan(Regexp.union(/\<td nowrap\>\$_POST\[(.+?)\]\<\/td\>/,/\<td nowrap\>\$HTTP_POST_VARS\[(.+?)\]\<\/td\>/,/\<td nowrap\>\$HTTP_RAW_POST_DATA\[(.+?)\]\<\/td\>/)).uniq().each() do |variable|
post+=variable.compact().join()+"=&" 
end
post = post.chomp("&")
#||++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Remake
files = ""
body.scan(Regexp.union(/\<td nowrap\>\$_FILES\[(.+?)\]\<\/td\>/)).uniq().each() do |variable|
files+=variable.compact().join()+"=&" 
end
files = files.chomp("=&")
#||++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Remake
cookie = ""
body.scan(Regexp.union(/\<td nowrap\>\$_COOKIE\[(.+?)\]\<\/td\>/,/\<td nowrap\>\$HTTP_COOKIE_VARS\[(.+?)\]\<\/td\>/)).uniq().each() do |variable|
cookie+=variable.compact().join()+"=;"
end
#||
if(get.empty?() == false)
variations = <<VARIATIONS
=0
=1
=true
=false
VARIATIONS
variations.split("\n").each() do |variation|
begin
variation = get.gsub("=", variation)
proxy.get(url+"?"+variation)
rescue Exception => e
if(e.inspect().include?("Net::HTTP::Persistent") == false && e.inspect().include?("Net::HTTPForbidden") == false && e.page().body().empty?() == false)
error = <<ERROR
#{"="*30}
[-] #{e.inspect()}
[*] #{e.page().body().inspect()}
#{"="*30}
ERROR
puts(error)
end
else
puts(url+" [GET] @"+variation+"@ ")
end
end
end
#||
if(request.empty?() == false)
variations = <<VARIATIONS
=0
=1
=true
=false
VARIATIONS
variations.split("\n").each() do |variation|
begin
variation = request.gsub("=", variation)
proxy.get(url+"?"+variation)
rescue Exception => e
if(e.inspect().include?("Net::HTTP::Persistent") == false && e.inspect().include?("Net::HTTPForbidden") == false && e.page().body().empty?() == false)
error = <<ERROR
#{"="*30}
[-] #{e.inspect()}
[*] #{e.page().body().inspect()}
#{"="*30}
ERROR
puts(error)
end
else
puts(url+" [REQUEST] @"+variation+"@ ")
end
end
end
#||
if(post.empty?() == false)
variations = <<VARIATIONS
=0
=1
=true
=false
VARIATIONS
variations.split("\n").each() do |variation|
begin
variation = post.gsub("=", variation)
proxy.post(url, variation)
rescue Exception => e
if(e.inspect().include?("Net::HTTP::Persistent") == false && e.inspect().include?("Net::HTTPForbidden") == false && e.page().body().empty?() == false)
error = <<ERROR
#{"="*30}
[-] #{e.inspect()}
[*] #{e.page().body().inspect()}
#{"="*30}
ERROR
puts(error)
end
else
puts(url+" [POST] @"+variation+"@ ")
end
end
end
#||
if(cookie.empty?() == false)
variations = <<VARIATIONS
=0
=1
=true
=false
=#{SecureRandom.hex(2)}
VARIATIONS
variations.split("\n").each() do |variation|
begin
variation = cookie.gsub("=", variation)
proxy.post(url, "", {"Cookie" => variation})
rescue Exception => e
if(e.inspect().include?("Net::HTTP::Persistent") == false && e.inspect().include?("Net::HTTPForbidden") == false && e.page().body().empty?() == false)
error = <<ERROR
#{"="*30}
[-] #{e.inspect()}
[*] #{e.page().body().inspect()}
#{"="*30}
ERROR
puts(error)
end
else
puts(url+" [COOKIE] @"+variation+"@ ")
end
end
end
#||
#||++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Remake
if(files.empty?() == false)
begin
multipart = <<MULTIPART
----------010101010
Content-Disposition: form-data; name="#{files}"

#{SecureRandom.hex(2)}
----------010101010--
MULTIPART
proxy.post(url, multipart, {"Content-Type" => "multipart/form-data; boundary=--------010101010"})
rescue Exception => e
if(e.inspect().include?("Net::HTTP::Persistent") == false && e.inspect().include?("Net::HTTPForbidden") == false && e.page().body().empty?() == false)
error = <<ERROR
#{"="*30}
[-] #{e.inspect()}
[*] #{e.page().body().inspect()}
#{"="*30}
ERROR
puts(error)
end
else
puts(url+" [FILES] @"+files+"@ ")
puts(multipart)
end
end
#||++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Remake
#||
end
end
end
#------------------------------------------------------------------------------------
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def compare(distribution,original,backup)
banner = <<BANNER

#{"!"*60}
# Module Original And Backup Comparison
#{"!"*60}
BANNER
puts(banner)
#
puts(`ruby #{distribution}/compare.rb -v #{distribution}/#{original} #{distribution}/#{backup}`)
end
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
def list(ext,rpath)
banner = <<BANNER

#{"!"*60}
# Module Extension Files Listing
#{"!"*60}
BANNER
puts(banner)
#
Dir.glob("**/*."+ext).each() do |path|
puts(rpath+path)
end
end
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
def grep(rpath,string)
banner = <<BANNER

#{"!"*60}
# Module All Files Matching
#{"!"*60}
BANNER
puts(banner)
#
Dir.glob("**/*.*").each() do |file|
begin
path = rpath+file
read = File.new(path, "r+").read().each_line() do |line|
line = line.inspect()
if(line.empty?() == false && line.include?(string) == true)
result = <<RESULT
[#{string.inspect()}] #{path} || #{line}
RESULT
puts(result)
end
end
rescue
else
end
end
end
#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ENABLE()/#DISABLE()
folders(rurl,agent)
files(rurl,agent,proxy,strings,rpath)
extension()
audit(rurl,rpath,agent,proxy)
compare(distribution,original,backup)
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ENABLE()/#DISABLE()
#list("", rpath)
#grep(rpath, "")
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ENABLE()/#DISABLE()
