  $(document).ready(function(){
      $("#assignForm").on("submit", function(event){
           $("#successAlert").text("Please wait.. Uploading Data").show();
           $.ajax({
                 data: {
                     driver_id: $("#driver_id").val(),   //get make from input
                     reg_no: $("#reg_no").val(),
                     from: $("#from").val(),
                     to: $("#to").val(),
                     scheduled_date: $("#scheduled_date").val(),
                     scheduled_time: $("#scheduled_time").val()
                 },//end data
                 type: 'POST',
                 url:"/assign/"+$("#driver_id").val()
           })//end ajax
           //Wait for response from Python without reloading Page
           .done(function(data){
                 if(data.error){
                      //handle error
                      $("#errorAlert").text(data.error).show();
                      $("#successAlert").hide();
                 }
                 else {
                    //Handle a success
                      $("#errorAlert").hide();
                      $("#successAlert").text(data.success).show();
                      $("#from").val("");   $("#to").val("");
                 }
           });//end done
           event.preventDefault();
      });//end submit
  });//end ready