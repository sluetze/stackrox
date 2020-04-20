import React from 'react';
import PropTypes from 'prop-types';

import SaveButton from 'Components/SaveButton';

function Button(props) {
    if (!props.isEditing)
        return (
            <button
                className="border-2 bg-primary-200 border-primary-400 text-sm text-primary-700 hover:bg-primary-300 hover:border-primary-500 rounded-sm block px-3 py-2 uppercase"
                type="button"
                onClick={props.onEdit}
                disabled={props.disabled}
            >
                {props.text}
            </button>
        );
    return (
        <div className="flex">
            <button className="btn btn-base mr-2" type="button" onClick={props.onCancel}>
                Cancel
            </button>
            <SaveButton formName="auth-provider-form" />
        </div>
    );
}

Button.propTypes = {
    text: PropTypes.string.isRequired,
    isEditing: PropTypes.bool.isRequired,
    onEdit: PropTypes.func.isRequired,
    onCancel: PropTypes.func.isRequired,
    disabled: PropTypes.bool.isRequired,
};

export default Button;
