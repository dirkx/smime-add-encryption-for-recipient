

smime-add-encrypt(1)      BSD General Commands Manual     smime-add-encrypt(1)

NNAAMMEE
     ssmmiimmee--aadddd--eennccrryypptt,, -- Add receipients to an encrypted s/mime message.

SSYYNNOOPPSSIISS
     ssmmiimmee--aadddd--eennccrryypptt,, [--vvhh] [--oo _o_u_t_f_i_l_e] [--pp _k_e_y_f_i_l_e] [--PP _c_e_r_t_f_i_l_e]
                        [--cc _c_e_r_t_s_f_i_l_e] [_i_n_f_i_l_e]

DDEESSCCRRIIPPTTIIOONN
     The ssmmiimmee--aadddd--eennccrryypptt,, utility complements the openssl(1) suite, it
     allows for the adding of one or more receipients to an encrypted s/mime
     message. In order to do so it will need the decryption key (i.e. the pri-
     vate key) of at least one of the existing recipients and one or more cer-
     tificate of the recipients to be added.

     Using the private key of a recipient it will decrypt the symmetric mes-
     sage encryption key; re-encrypt it against the public keys of the new
     recipients; and then add the right information to the s/mime structure.

     A list of flags and their descriptions:

     --oo _o_u_t_f_i_l_e
              The resulting S/MIME file; if none specified; output is send to
              stdout.

     --pp _k_e_y_f_i_l_e
              The private key of an existing recipient in PEM format.

     --PP _c_e_r_t_-_f_i_l_e
              An X509 certificate (PEM format) of an existing recipient. When
              not present we try to decode the entry for each recipient and
              hope that the first match was indeed the right one.

     --CC _c_e_r_t_s_-_f_i_l_e
              A file containing one or more X509 certificate (PEM) format of
              the recipients to be added. Can be repeated.

     --hh       Help, Provides a short synopsis of the flags and then exists.

     --vv       Provide verbose information on standard error.

     _i_n_f_i_l_e   The S/MIME file to add recipients too. If not specified stdin is
              assumed. The format can be either raw PKCS7 or PEM.

SSEEEE AALLSSOO
     openssl(1), smime(1),

BBUUGGSS
     Does not accept the full width of openssl's formats and engine settings.

HHIISSTTOORRYY
     Written by Dirk-Willem van Gulik, 2023 - Apache Software Foundation
     License 2.0 or newer.

Darwin                         February 26, 2013                        Darwin
