<pre>

smime-add-encrypt(1)      BSD General Commands Manual     smime-add-encrypt(1)

NAME
     smime-add-encrypt, -- Add receipients to an encrypted s/mime message.

SYNOPSIS
     smime-add-encrypt, [-vh] [-o outfile] [-p keyfile] [-P certfile]
                        [-c certsfile] [infile]

DESCRIPTION
     The smime-add-encrypt, utility complements the openssl(1) suite, it
     allows for the adding of one or more receipients to an encrypted s/mime
     message. In order to do so it will need the decryption key (i.e. the pri-
     vate key) of at least one of the existing recipients and one or more cer-
     tificate of the recipients to be added.

     Using the private key of a recipient it will decrypt the symmetric mes-
     sage encryption key; re-encrypt it against the public keys of the new
     recipients; and then add the right information to the s/mime structure.

     A list of flags and their descriptions:

     -o outfile
              The resulting S/MIME file; if none specified; output is send to
              stdout.

     -p keyfile
              The private key of an existing recipient in PEM format.

     -P cert-file
              An X509 certificate (PEM format) of an existing recipient. When
              not present we try to decode the entry for each recipient and
              hope that the first match was indeed the right one.

     -C certs-file
              A file containing one or more X509 certificate (PEM) format of
              the recipients to be added. Can be repeated.

     -h       Help, Provides a short synopsis of the flags and then exists.

     -v       Provide verbose information on standard error.

     infile   The S/MIME file to add recipients too. If not specified stdin is
              assumed. The format can be either raw PKCS7 or PEM.

SEE ALSO
     openssl(1), smime(1),

BUGS
     Does not accept the full width of openssl's formats and engine settings.

HISTORY
     Written by Dirk-Willem van Gulik, 2023 - Apache Software Foundation
     License 2.0 or newer.

Darwin                         February 26, 2013                        Darwin

</pre>
