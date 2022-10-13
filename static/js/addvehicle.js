  $(document).ready(function(){
      $("#vehicleForm").on("submit", function(event){
           $("#success").text("Please wait.. Uploading Data").show();

           var form_data = new FormData();
           form_data.append("files[]", document.getElementById("passport_pic").files[0])
           form_data.append("reg_no", $("#reg_no").val())
           form_data.append("type_id", $("#type_id").val())
           form_data.append("make_id", $("#make_id").val())
           form_data.append("model_id", $("#model_id").val())
           form_data.append("capacity_id" , $("#capacity_id").val())
           form_data.append("color", $("#color").val())
           form_data.append("weight", $("#weight").val())
           form_data.append("no_of_pass",  $("#no_of_pass").val())
           form_data.append("year", $("#year").val())
           form_data.append("chassis_no", $("#chassis_no").val())
           form_data.append("year", $("#year").val())

           $.ajax({
                 data: form_data,
                 type: 'POST',
                 url:"/addVehicle/"+$("#owner_id").val(),
                 cache: false,
                 contentType: false,
                 processData: false
           })//end ajax
           //Wait for response from Python without reloading Page
           .done(function(data){
                 if(data.error){
                      //handle error
                      $("#error").text(data.error).show();
                      $("#error2").hide();
                      $("#success").hide();
                 }
                 else if(data.error2){
                     //handle error
                      $("#error2").text(data.error2).show();
                      $("#error").hide();
                      $("#success").hide();
                 }
                 else {
                    //Handle a success
                      $("#success").text(data.success).show();
                      $("#error2").hide();
                      $("#error").hide();
                 }
           });//end done
           event.preventDefault();
      });//end submit
  });//end ready