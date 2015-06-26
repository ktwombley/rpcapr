#libpcap requirements
#include <stdio.h>
#include <pcap.h>

#R requirements
#include <R.h>
#include <Rdefines.h>
#include <R_ext/Error.h>



SEXP _get_device(SEXP dev) {
  //input
  const char* devbuf;
  devbuf = translateChar(STRING_ELT(dev, 0));
  SEXP ret = R_NilValue;
  char *founddev, errbuf[PCAP_ERRBUF_SIZE];

  //libpcap call
  founddev = pcap_lookupdev(errbuf);

  //results check
  if (founddev == NULL) {
    error(sprintf("Couldn't find default device: %s\n", errbuf));
      ret = R_NilValue;
  }
  else {
    ret = PROTECT(allocVector(STRSXP, 1));
    SET_STRING_ELT(ret, 0, mkChar(founddev));
    UNPROTECT(1);
  }

  //output
  return(ret);
}


