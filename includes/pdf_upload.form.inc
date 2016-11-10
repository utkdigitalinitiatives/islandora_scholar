<?php

/**
 * @file
 * Module used to create the PDF upload step for Scholar.
 */

/**
 * Gets the upload form.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 *
 * @return array
 *   The Drupal form definition.
 */
function islandora_scholar_pdf_upload_form(array $form, array &$form_state) {
  $upload_size = min((int) ini_get('post_max_size'), (int) ini_get('upload_max_filesize'));

  // Pull document versions from the module settings if available.
  $document_versions = get_document_versions();

  // Pull use permissions from the module settings if available.
  $use_permissions = get_use_permissions();

  $form['upload_pdf_checkbox'] = array(
    '#type' => 'checkbox',
    '#title' => t('Would you like to include a PDF document for this citation?'),
  );
  $form['upload_document'] = array(
    '#type' => 'fieldset',
    '#title' => t('Upload Document'),
    '#states' => array(
      'visible' => array(
        ':input[name="upload_pdf_checkbox"]' => array('checked' => TRUE),
      ),
    ),
  );
  $form['upload_document']['file'] = array(
    '#type' => 'managed_file',
    '#title' => 'PDF file',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array('pdf'),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_document']['version'] = array(
    '#type' => 'radios',
    '#title' => t('Document Version'),
    '#options' => $document_versions,
  );
  $form['upload_document']['usage'] = array(
    '#type' => 'radios',
    '#title' => t('Use Permission'),
    '#options' => $use_permissions,
  );
  $form['upload_document']['certifying'] = array(
    '#type' => 'checkboxes',
    '#title' => t('Certify'),
    '#options' => array(
      'certify' => t('I certify that I have the right to upload this version.'),
    ),
  );
  $form['supply_supplemental'] = array(
    '#type' => 'checkbox',
    '#title' => t('Would you like to include supplemental files with this ETD?'),
  );
  $form['upload_supplemental'] = array(
    '#type' => 'fieldset',
    '#title' => t('Upload Supplemental Files'),
    '#states' => array(
      'visible' => array(
        ':input[name="supply_supplemental"]' => array('checked' => TRUE),
      ),
    ),
  );
  $form['upload_supplemental']['set1']['file1'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 1',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental']['set1']['file2'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 2',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental']['set1']['file3'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 3',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental']['set1']['file4'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 4',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental']['set1']['file5'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 5',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental']['supply_supplemental2'] = array(
    '#type' => 'checkbox',
    '#title' => t('Would you like to include additional supplemental files with this ETD?'),
    $form['upload_supplemental2'] = array(
      '#type' => 'fieldset',
      '#title' => t('Additional Supplemental Files'),
      '#states' => array(
        'visible' => array(
          ':input[name="supply_supplemental2"]' => array('checked' => TRUE),
        ),
      ),
    ),
  );
  $form['upload_supplemental2']['set2']['file6'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 6',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental2']['set2']['file7'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 7',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental2']['set2']['file8'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 8',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental2']['set2']['file9'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 9',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental2']['set2']['file10'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 10',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    ),
  );
  $form['upload_supplemental2']['supply_supplemental3'] = array(
    '#type' => 'checkbox',
    '#title' => t('Would you like to include additional supplemental files with this ETD (Part II)?'),
    $form['upload_supplemental3'] = array(
      '#type' => 'fieldset',
      '#title' => t('Additional Supplemental Files, Part II'),
      '#states' => array(
        'visible' => array(
          ':input[name="supply_supplemental3"]' => array('checked' => TRUE),
        ),
      ),
    ),
  );
  $form['upload_supplemental3']['set3']['file11'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 11',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file12'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 12',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file13'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 13',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file14'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 14',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file15'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 15',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['supply_supplemental4'] = array(
    '#type' => 'checkbox',
    '#title' => t('Would you like to include additional supplemental files with this ETD (Part III)?'),
    $form['upload_supplemental4'] = array(
      '#type' => 'fieldset',
      '#title' => t('Additional Supplemental Files, Part III'),
      '#states' => array(
        'visible' => array(
          ':input[name="supply_supplemental4"]' => array('checked' => TRUE),
        ),
      ),
    ),
  );
  $form['upload_supplemental3']['set3']['file16'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 16',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file17'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 17',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file18'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 18',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file19'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 19',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
  $form['upload_supplemental3']['set3']['file20'] = array(
    '#type' => 'managed_file',
    '#title' => 'Supplemental File 20',
    '#upload_location' => 'temporary://',
    '#upload_validators' => array(
      'file_validate_extensions' => array(),
      'file_validate_size' => array($upload_size * 1024 * 1024),
    )
  );
return $form;
}

/**
 * Validation for the Islandora Scholar PDF upload form.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 */
function islandora_scholar_pdf_upload_form_validate($form, $form_state) {
  if ($form_state['values']['upload_pdf_checkbox']) {
    if (empty($form_state['values']['file'])) {
      form_set_error('file', t('A file must be uploaded!'));
    }
    if (empty($form_state['values']['version'])) {
      form_set_error('version', t('A document version must be selected!'));
    }
    if (empty($form_state['values']['usage'])) {
      form_set_error('usage', t('A usage permission must be selected!'));
    }
    if (empty($form_state['values']['certifying']['certify'])) {
      form_set_error('certifying', t('You must certify that you have the right to upload this PDF!'));
    }
    if (empty($form_state['values']['supply_supplemental'])) {
      form_set_error('supply_supplemental', t('A supplemental file must be uploaded!'));
    }
    if (empty($form_state['values']['supply_supplemental2'])) {
      form_set_error('supply_supplemental', t('A supplemental file must be uploaded!'));
    }
    if (empty($form_state['values']['supply_supplemental3'])) {
      form_set_error('supply_supplemental', t('A supplemental file must be uploaded!'));
    }
    if (empty($form_state['values']['supply_supplemental4'])) {
      form_set_error('supply_supplemental', t('A supplemental file must be uploaded!'));
    }
  }
}

/**
 * Upload form Submit handler, adds PDF datastream.
 *
 * Also updates the MODS usage and version for the PDF datastream.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 */
function islandora_scholar_pdf_upload_form_submit(array $form, array &$form_state) {
  if ($form_state['values']['upload_pdf_checkbox']) {
    $object = islandora_ingest_form_get_object($form_state);
    module_load_include('inc', 'islandora_scholar', 'includes/upload.tab');
    $file = file_load($form_state['values']['file']);
    $datastream = $object->constructDatastream('PDF', 'M');
    $datastream->label = $file->filename;
    $datastream->mimetype = 'application/pdf';
    $datastream->setContentFromFile($file->uri, FALSE);
    $object->ingestDatastream($datastream);
    islandora_scholar_add_usage_and_version_elements_to_mods($object, $form_state['values']['usage'], $form_state['values']['version']);
  }
  if ($form_state['values']['supply_supplemental']) {
    $object = islandora_ingest_form_get_object($form_state);
    module_load_include('inc', 'islandora_scholar', 'includes/upload.tab');
    $file = file_load($form_state['values']['file1']);
    $datastream = $object->constructDatastream('SUPPL_0', 'M');
    $datastream->label = $file->filename;
    $datastream->mimetype = 'application/octet-stream';
    // look at is_file as a check for this section
  }
}

/**
 * Undo submit handler for the PDF upload ingest step for Scholar.
 *
 * @param array $form
 *   The Drupal form definition.
 * @param array $form_state
 *   The Drupal form state.
 */
function islandora_scholar_pdf_upload_form_undo_submit(array $form, array &$form_state) {
  $object = islandora_ingest_form_get_object($form_state);
  $object->purgeDatastream('PDF');
}
