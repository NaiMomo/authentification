/**
 * Pour faire disparaitre les popups jaunes de messages apres quelque secondes
 * */
function fadePopUp(){
   $(document).ready(function(){
   $(".alert_pop_up").fadeOut(6000);
});
}
/**
 * Lorsque l'admin click sur une action de la table d'utilisateur, une boite de dialoge apparait,
 * cette boite est faite par cette fonction, qui envoie ces valeurs a app.py*/
function comfirmPasswdPopUp(action, username, new_pass= null) {
    console.log(username.toString())
    var passwordInput = document.createElement('input');
    passwordInput.type = 'password';
    passwordInput.placeholder = 'Votre mot de passe';
    var confirmedPass = null;
    var displayedMsg = "\nConfirmez votre action pour: " + username

    var dialog = bootbox.dialog({
        title: displayedMsg ,
        message: passwordInput,
        inputType: 'password',
        buttons: {
            cancel: {
                label: 'Annuler',
                className: 'btn-danger',
                callback: function() {}
            },
            confirm: {
                label: 'Confirmer',
                className: 'btn-primary',
                callback: function() {
                    confirmedPass = passwordInput.value;
                }
            }
        }
    });

    dialog.init(function() {
        passwordInput.focus();
    });

    dialog.on('shown.bs.modal', function() {
        passwordInput.focus();
    });

    dialog.on('hidden.bs.modal', function() {
        if (confirmedPass !== null && confirmedPass !== '') {
            $.ajax({
                type: 'POST',
                url: '/allow_admin_op',
                data: { confirmation: confirmedPass, action: action, username: username, new_pass: new_pass},

            });
        }
    });
}
