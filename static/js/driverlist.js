$(document).ready(function(){
     function load_data(search_word){
        $.ajax({
             url: "/driverlivesearch",
             method: "POST",
             data: {search_word:search_word},
             success: function(data){
                   $("#result").html(data);
                   $("#result").append(data.htmlresponse);
             }
        }); //end ajax
     }//end load

     $("#search_word").keyup(function(){
          let search_word = $("#search_word").val();
          if(search_word != ''){
              load_data(search_word);
          }
          else {
              load_data('');
          }
     });
}); //end Ready