#' rpcapr: Put pcap in your R.
#'
#' This is an R library for capturing, reading, and analyzing libpcap packet
#' capture files. My initial goal is to be able to open an existing pcap file
#' and import it into R as a data frame. Future development goals are to allow 
#' R to write a pcap file and to perform live capture.
#'
#' Tools for working with libpcap packet capture files.
#'
#' @docType package
#' @import rdyncall
#' @name rpcapr
NULL


.onUnload <- function (libpath) {
  library.dynam.unload("rpcapr", libpath)
}

#' A representation of a pcap file
#'
#' \code{pcap} objects handle reading packets from a pcap file stored on disk.
#'
#' This function prepares a pcap file for reading. 
#'
#' @param file A path or filename to the pcap file.
#' @return pcap
#' @references http://www.tcpdump.org/manpages/pcap.3pcap.html
#' @export
#' @examples
#' a <- pcap("capturefile.pcap")
#' print(length(a))
#' b <- ip("anothercapture.pcap")
#' print(b[3])
pcap <- function(description) {
	eb <- raw(PCAP_ERRBUF_SIZE)

	f <- file(description, raw=TRUE)
	pcap_handle <- as.struct(c_pcap_open_offline(description, eb), "pcap_t")
	if (is.nullptr(pcap_handle)) {
		stop(sprintf("Could not open '%s', libpcap said: '%s'", description, rawToChar(eb)))
	}
	structure(f, 
		pcap_handle = pcap_handle,
		class = c("pcap", class(f)),
		errorbuffer = eb)
}


# Need to open up R's file connection guts.
# typedef struct fileconn {
#    FILE *fp;
#    OFF_T rpos, wpos;
#    Rboolean last_was_write;
#    Rboolean raw;
# #ifdef Win32
#    Rboolean anon_file;
#    char name[PATH_MAX+1];
# #endif
# } *Rfileconn;
parseStructInfos("
fileconn{*<fp>jjIIIc}fp rpos wpos last_was_write raw anon_file name;")


