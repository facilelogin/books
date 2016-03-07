
1. Create keystore

keytool -genkey -alias apress -keyalg RSA -keysize 2048 -dname "CN=apress,C=US" -keypass password -keystore apress.jks -storepass password


2. Export public certificate

keytool -export -alias apress -keystore apress.jks -storepass password -file apress.crt
