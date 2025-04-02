class Checkbox extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: "open" });

        this.shadowRoot.innerHTML = `
            <style>
                :host {
                    display: flex;
                    align-items: center;
                    font-family: Arial, sans-serif;
                    cursor: pointer;
                }
                input {
                    margin-right: 5px;
                }
            </style>
            <label>
                <input type="checkbox">
                <slot></slot>
            </label>
        `;
    }
}

customElements.define("opnsense-checkbox", Checkbox);