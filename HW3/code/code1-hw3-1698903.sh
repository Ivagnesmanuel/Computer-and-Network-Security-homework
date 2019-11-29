password=$(openssl rand -base64 32)

echo "Measures for CBC are:"
for ((i = 1 ; i < 4 ; i++)); do
	echo "the $i encryption took:"
  time openssl enc -aes-256-cbc -pbkdf2 -in CNS0.pdf -out out.enc -pass pass:$password
	echo " "

	echo "the $i decryption took:"
	time openssl enc -aes-256-cbc -pbkdf2 -d -in out.enc -out CNS0.pdf -pass pass:$password
	echo " "
done


echo "Measures for GCM are:"
for ((i = 1 ; i < 4 ; i++)); do
	echo "the $i encryption took:"
  time openssl enc -aes-256-gcm -in CNS0.pdf -out out.enc -pass pass:$password
	echo " "

	echo "the $i decryption took:"
	time openssl enc -aes-256-gcm -d -in out.enc -out CNS0.pdf -pass pass:$password
	echo " "
done
