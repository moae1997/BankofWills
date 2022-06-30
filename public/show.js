
const showWill = document.querySelector("#showWill");
const addWill = document.querySelector("#addWill");
const showDiv = document.querySelector("#showDiv");
const addDiv = document.querySelector("#addDiv");



showWill.addEventListener("click", e => {

        e.preventDefault();
        addDiv.classList.remove("hide");
        showDiv.classList.add("hide");


});

addWill.addEventListener("click", e => {

    e.preventDefault();
    addDiv.classList.add("hide");
    showDiv.classList.remove("hide");


});

