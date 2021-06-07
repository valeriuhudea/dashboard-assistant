"use strict";

$(function() {
var $cookieBanner = $( "#cookie-policy-banner" );
   if( $cookieBanner.length ) {
       $cookieBanner.find( "button" ).click(function() {
            var choice = $( this ).data( "choice" );
                if( $.isNumeric(choice) && choice !== 0) {
                    $("#cookie-policy-banner").hide()
                } else {
                    window.location.replace("https://wpp.com")
                }
            });
        };
})
