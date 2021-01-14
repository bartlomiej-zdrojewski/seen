document.addEventListener('DOMContentLoaded', function (event) {
    const CREATE_BUTTON_ID = "button_create"
    const POST = "POST";
    const HTTP_STATUS = {
        OK: 200,
        CREATED: 201
    };

    init();

    function init() {
        const createButton = document.getElementById(CREATE_BUTTON_ID)
        createButton.addEventListener("click", e => onCreate(e));
    }

    function onCreate(event) {
        event.preventDefault();
        const url = "/api/note";
        const params = {
            method: POST,
            redirect: "follow"
        };
        fetch(url, params)
            .then(response => {
                if (response.status === HTTP_STATUS.CREATED) {
                    response.json()
                        .then(data => {
                            window.location.href = data.redirect_url;
                        })
                        .catch(error => console.log(error))
                } else {
                    response.json()
                        .then(data => console.log(data.error_message))
                        .catch(error => console.log(error))
                }
            });
    }
});
