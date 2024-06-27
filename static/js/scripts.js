/**
 * Code utilisé dans la page d'accueil, pour obtenir les parametres dans le backend
 * **/

$("form[name=login_form").submit(function(e) {

  var $form = $(this);
  var $error = $form.find(".error"); // Trouver le paragraphe caché (tentatives etc)
  var data = $form.serialize(); // pour obtnir les parametes session['user'], ils seront envoyés de route vers user()

  $.ajax({
    url: "/user/login",
    type: "POST",
    data: data,
    dataType: "json",
    success: function(resp) {
      window.location.href = "/dashboard/";
    },
    error: function(resp) {
      $error.text(resp.responseJSON.error).removeClass("error--hidden");
    }
  });

  e.preventDefault();
});