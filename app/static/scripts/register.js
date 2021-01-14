document.addEventListener('DOMContentLoaded', function (event) {
    const FORM_ID = "form";
    const POST = "POST";
    const HTTP_STATUS = {
        OK: 200,
        CREATED: 201
    };

    init();

    function init() {
        const form = document.getElementById(FORM_ID);
        form.addEventListener("submit", e => onSubmit(e));
    }

    function updateStatus(text, isError) {
        const form = document.getElementById(FORM_ID);
        let status = form.getElementsByClassName("alert")[0];
        if (!status) {
            form.innerHTML += "<div class=\"mt-3 alert\"></div>";
            status = form.getElementsByClassName("alert")[0];
        }
        status.innerHTML = text;
        if (isError === true) {
            status.classList.remove('alert-primary');
            status.classList.add('alert-danger');
        } else {
            status.classList.add('alert-primary');
            status.classList.remove('alert-danger');
        }
    }

    function onSubmit(event) {
        event.preventDefault();
        const form = document.getElementById(FORM_ID);
        const url = "/api/user/register";
        const params = {
            method: POST,
            body: new FormData(form),
            redirect: "follow"
        };
        fetch(url, params)
            .then(response => {
                if (response.status === HTTP_STATUS.CREATED) {
                    response.json()
                        .then(data => {
                            window.location.href = data.redirect_url;
                            updateStatus("Registered successfully. Redirecting...");
                        })
                        .catch(error => updateStatus(error, true))
                } else {
                    response.json()
                        .then(data => updateStatus(data.error_message, true))
                        .catch(error => updateStatus(error, true))
                }
            });
    }
});
