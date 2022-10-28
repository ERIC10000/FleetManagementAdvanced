  $(document).ready(function(){
      $("#serviceForm").on("submit", function(event){
      $("#successAlert").text("Please wait.. Uploading Data").show();


      var array = [];
      $("#list").find("option:selected").map(function(){
           alert($(this).text());
           array.push($(this).text());
      })

      console.log(array);

           $.ajax({
                 data: {
                     reg_no: $("#reg_no").val(),
                     scheduled_date: $("#scheduled_date").val(),
                     scheduled_time: $("#scheduled_time").val(),
                     services: array
                 },//end data
                 type: 'POST',
                 url:"/send_service/"+$("#reg_no").val()
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
                      $("#services").val("");
                 }
           });//end done

           event.preventDefault();
      });//end submit
  });//end ready