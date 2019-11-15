# read each line of the file
while IFS= read -r line; do
	#decrypt and check if the file is composed only by ASCII values
	openssl enc -aes-192-cbc -pbkdf2 -d -in ciphertext.enc -out result.txt -pass pass:${line}
	if file result.txt | grep 'ASCII text'; then
		password=$line
		break
	fi
done < dictionary.txt

#print results on shell
echo "  "
echo "PASSWORD:" $password
echo "To read the decrypted message look at result.txt in the current folder "
echo "  "
