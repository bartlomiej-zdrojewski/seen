document.addEventListener('DOMContentLoaded', function (event) {
    const FORM_ID = "form";
    const CHECKBOX_IS_PUBLIC_ID = "checkbox_is_public"
    const DELETE_BUTTON_ID = "button_delete"
    const PUT = "PUT";
    const DELETE = "DELETE";
    const HTTP_STATUS = {
        OK: 200,
        CREATED: 201
    };

    init();

    function init() {
        const form = document.getElementById(FORM_ID);
        const checkboxIsPublic = document.getElementById(CHECKBOX_IS_PUBLIC_ID)
        const deleteButton = document.getElementById(DELETE_BUTTON_ID)
        checkboxIsPublic.checked = (checkboxIsPublic.value === "true")
        form.addEventListener("submit", e => onSubmit(e));
        checkboxIsPublic.addEventListener("click", e => updateIsPublicCheckbox(e));
        deleteButton.addEventListener("click", e => onDelete(e));
        updateIsPublicCheckbox()
    }

    function updateIsPublicCheckbox(event) {
        const checkboxIsPublic = document.getElementById(CHECKBOX_IS_PUBLIC_ID)
        if (checkboxIsPublic.checked) {
            checkboxIsPublic.value = "true"
        } else {
            checkboxIsPublic.value = "false"
        }
    }

    // TODO fix overwriting sharing link
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
        const formData = new FormData(form);
        if (formData.get("is_public") == null) {
            formData.set("is_public", "false");
        }
        const url = "/api/note/" + formData.get("code");
        const params = {
            method: PUT,
            body: formData,
            redirect: "follow"
        };
        fetch(url, params)
            .then(response => {
                if (response.status === HTTP_STATUS.OK) {
                    updateStatus("Updated successfully.");
                } else {
                    response.json()
                        .then(data => updateStatus(data.error_message, true))
                        .catch(error => updateStatus(error, true))
                }
            });
    }

    function onDelete(event) {
        event.preventDefault();
        const form = document.getElementById(FORM_ID);
        const formData = new FormData(form);
        const url = "/api/note/" + formData.get("code");
        const params = {
            method: DELETE,
            redirect: "follow"
        };
        fetch(url, params)
            .then(response => {
                if (response.status === HTTP_STATUS.OK) {
                    response.json()
                        .then(data => {
                            window.location.href = data.redirect_url;
                            updateStatus("Deleted successfully. Redirecting...");
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
