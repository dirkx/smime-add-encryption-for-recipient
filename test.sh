true > all.pem
for i in alice bob dave newborn1 newborn2
do
	test -r $i.crt ||\
	openssl req -new -x509 -subj /CN=u$i -keyout /dev/stdout -nodes > $i.crt
	cat $i.crt >> all.pem
done

(
#	dd if=/dev/urandom count=1024 bs=1024 | base64
	echo today is
	date
	echo .
)| openssl smime -encrypt *.crt | tee msg.smime | openssl smime -pk7out  | tee msg.pkcs7 | openssl asn1parse  -dump

./smime-add-recipient -v -c newborn2.crt  -c newborn1.crt  -p bob.crt  -P bob.crt  msg.pkcs7 |  openssl smime -pk7out  | openssl asn1parse  -dump

./smime-add-recipient -c newborn1.crt  -p bob.crt  -P bob.crt  msg.pkcs7 |\
 	openssl smime -decrypt -recip bob.crt
./smime-add-recipient -c newborn1.crt  -p bob.crt  -P bob.crt  msg.pkcs7 |\
 	openssl smime -decrypt -recip newborn1.crt
./smime-add-recipient -c newborn2.crt  -p bob.crt  msg.pkcs7 |\
 	openssl smime -decrypt -recip newborn2.crt


